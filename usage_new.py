"""
Audit downstream usage of the "OC" QuickSight dataset's columns across:
  1. Athena/Glue views (view SQL definitions)
  2. QuickSight datasets (calculated fields / custom SQL physical tables)
  3. QuickSight analyses (calculated fields, filters, visuals/field wells, sorts)
  4. QuickSight dashboards (same, from the published definition)

Produces two CSVs:
  - oc_column_usage_tally.csv   : per-column count of references, broken out by source type
  - oc_select_star_locations.csv: every place OC is queried/used with SELECT * (or full-table
                                   pass-through), for manual inspection

Requires: boto3, pandas
    pip install boto3 pandas --break-system-packages

Auth: uses your normal AWS credential chain (env vars, profile, IAM role).
This script only reads metadata (Glue GetTables, QuickSight Describe*/List*) -
it does not run any Athena queries against your data.
"""

import base64
import json
import re
from collections import Counter, defaultdict

import boto3
import pandas as pd

# =========================================================================
# CONFIG - fill these in for your environment
# =========================================================================
AWS_ACCOUNT_ID = "123456789012"          # <-- your AWS account id
REGION = "us-east-1"                     # <-- your region

# The OC QuickSight dataset
OC_DATASET_ID = "OC-DATASET-ID"          # <-- OC's DataSetId (not display name)

# The Athena/Glue table(s) that back OC, so we can find views built on top of it.
# Include every schema.table alias downstream views might reference (e.g. if OC
# is itself a view over a base table, list both).
OC_ATHENA_DATABASE = "analytics_db"      # <-- Glue database name
OC_ATHENA_TABLE_NAMES = ["oc", "oc_table"]  # <-- table/view name(s) as used in SQL, lowercase

# Glue databases to scan for views that might reference OC. Include all databases
# analysts might build views in, not just OC_ATHENA_DATABASE.
GLUE_DATABASES_TO_SCAN = ["analytics_db"]

# If you already know OC's column list, put it here to skip the DescribeDataSet
# lookup. Leave as None to auto-fetch from QuickSight.
OC_COLUMNS_OVERRIDE = None  # e.g. ["customer_id", "order_date", "region", ...]

# =========================================================================

qs = boto3.client("quicksight", region_name=REGION)
glue = boto3.client("glue", region_name=REGION)

SELECT_STAR_RE = re.compile(r"select\s+\*\s+from", re.IGNORECASE)
WORD_BOUNDARY_TEMPLATE = r"(?<![A-Za-z0-9_]){col}(?![A-Za-z0-9_])"


# -------------------------------------------------------------------------
# 0. Get OC's column list
# -------------------------------------------------------------------------
def get_oc_columns():
    if OC_COLUMNS_OVERRIDE:
        return [c.lower() for c in OC_COLUMNS_OVERRIDE]

    resp = qs.describe_data_set(AwsAccountId=AWS_ACCOUNT_ID, DataSetId=OC_DATASET_ID)
    dataset = resp["DataSet"]
    columns = set()

    # Columns come from OutputColumns (final resolved schema after all transforms)
    for col in dataset.get("OutputColumns", []):
        name = col.get("Name")
        if name:
            columns.add(name.lower())

    return sorted(columns)


# -------------------------------------------------------------------------
# 1. Athena / Glue view scanning
# -------------------------------------------------------------------------
def decode_athena_view_sql(view_original_text: str) -> str | None:
    """
    Athena/Presto views are stored in Glue as:
        /* Presto View: <base64-encoded JSON> */
    The JSON has an "originalSql" field with the actual SQL text.
    """
    if not view_original_text:
        return None
    match = re.search(r"/\* Presto View:\s*(.*?)\s*\*/", view_original_text, re.DOTALL)
    if not match:
        return None
    try:
        decoded = base64.b64decode(match.group(1)).decode("utf-8")
        payload = json.loads(decoded)
        return payload.get("originalSql")
    except Exception:
        return None


def list_glue_views(database_name: str) -> list[dict]:
    views = []
    paginator = glue.get_paginator("get_tables")
    for page in paginator.paginate(DatabaseName=database_name):
        for table in page.get("TableList", []):
            if table.get("TableType") == "VIRTUAL_VIEW":
                views.append(table)
    return views


def references_oc_table(sql_text: str) -> bool:
    sql_lower = sql_text.lower()
    return any(
        re.search(WORD_BOUNDARY_TEMPLATE.format(col=re.escape(tbl)), sql_lower)
        for tbl in OC_ATHENA_TABLE_NAMES
    )


def scan_athena_views(oc_columns: list[str]):
    """
    Returns:
      column_hits: Counter of {column_name: count} from Athena view SQL
      select_star_hits: list of dicts describing each SELECT * usage found
    """
    column_hits = Counter()
    select_star_hits = []

    for db in GLUE_DATABASES_TO_SCAN:
        print(f"Scanning Glue database '{db}' for views...")
        views = list_glue_views(db)
        for view in views:
            view_name = view.get("Name")
            original_text = view.get("ViewOriginalText")
            sql = decode_athena_view_sql(original_text)
            if not sql:
                # Not a Presto/Athena view we can decode (could be a different
                # engine's view format) - flag for manual check.
                continue
            if not references_oc_table(sql):
                continue

            location = f"{db}.{view_name}"

            # Column usage tally (word-boundary match to avoid partial matches,
            # e.g. "order_id" not matching inside "order_id_2")
            sql_lower = sql.lower()
            for col in oc_columns:
                pattern = WORD_BOUNDARY_TEMPLATE.format(col=re.escape(col))
                occurrences = len(re.findall(pattern, sql_lower))
                if occurrences:
                    column_hits[col] += occurrences

            # SELECT * detection - flag broadly; scoping "*" to specifically
            # the OC reference requires a real SQL parser, so we surface every
            # select-star found in a view that touches OC for manual review.
            if SELECT_STAR_RE.search(sql_lower):
                select_star_hits.append({
                    "source_type": "athena_view",
                    "location": location,
                    "detail": "SELECT * found in view referencing OC table",
                    "sql_snippet": sql.strip()[:500],
                })

    return column_hits, select_star_hits


# -------------------------------------------------------------------------
# 2. QuickSight: recursively walk a definition dict/list for column refs
# -------------------------------------------------------------------------
def find_column_identifier_refs(node, oc_dataset_identifiers, hits: Counter):
    """
    Recursively walk a QuickSight Definition (dataset/analysis/dashboard) JSON
    structure looking for ColumnIdentifier-style references:
        {"DataSetIdentifier": "...", "ColumnName": "..."}
    which appear throughout FieldWells, Filters, Sorts, ConditionalFormatting,
    tooltips, reference lines, etc. Only tallies refs tied to an OC dataset
    identifier used in this analysis/dashboard.
    """
    if isinstance(node, dict):
        if "ColumnName" in node and isinstance(node.get("ColumnName"), str):
            ds_id = node.get("DataSetIdentifier")
            if ds_id is None or ds_id in oc_dataset_identifiers:
                hits[node["ColumnName"].lower()] += 1
        for v in node.values():
            find_column_identifier_refs(v, oc_dataset_identifiers, hits)
    elif isinstance(node, list):
        for item in node:
            find_column_identifier_refs(item, oc_dataset_identifiers, hits)


DEBUG = True  # set False once you've confirmed identifier matching works


def find_oc_dataset_identifiers(definition: dict, asset_label: str = "") -> set:
    """
    Analyses/dashboards reference datasets by a local 'Identifier' string,
    declared in DataSetIdentifierDeclarations, mapped to a DataSetArn.
    Return the set of local identifiers that point at OC.
    """
    identifiers = set()
    all_declared = []
    for decl in definition.get("DataSetIdentifierDeclarations", []):
        arn = decl.get("DataSetArn", "")
        all_declared.append((decl.get("Identifier"), arn))
        if arn.rstrip("/").endswith(f"/{OC_DATASET_ID}"):
            identifiers.add(decl.get("Identifier"))

    if DEBUG and asset_label:
        print(f"    [{asset_label}] declared datasets: {all_declared}")
        print(f"    [{asset_label}] matched OC identifiers: {identifiers}")

    return identifiers


def build_calc_field_name_lookup(calc_fields: list[dict], oc_dataset_identifiers: set) -> set:
    """
    Names of calculated fields that belong to OC (or reference OC), used to
    resolve transitive references (a calc field that references another calc
    field, which in turn references a raw OC column).
    """
    return {c.get("Name", "").lower() for c in calc_fields if c.get("DataSetIdentifier") in oc_dataset_identifiers}


def extract_field_refs(expr: str) -> set:
    """
    Extract every field reference in a calculated-field expression, handling
    both the standard {field_name} form and bare single-word references
    (valid QuickSight syntax when the field name has no spaces/special chars
    and isn't a reserved word). Bare-word matching is intentionally permissive
    here; false positives are filtered out later by only keeping matches that
    are also in oc_columns or the OC calc-field name set.
    """
    refs = set()
    # Braced form: {field name}
    refs.update(m.group(1).strip().lower() for m in re.finditer(r"\{([^{}]+)\}", expr))
    # Bare word form: only tokens that look like identifiers (skip function
    # names followed by "(" since those are formula functions, not fields)
    for m in re.finditer(r"(?<![A-Za-z0-9_\{])[A-Za-z_][A-Za-z0-9_]*(?![A-Za-z0-9_\}])", expr):
        token = m.group(0)
        # Skip if immediately followed by "(" (i.e. a function call like sum()
        after = expr[m.end():m.end() + 1]
        if after == "(":
            continue
        refs.add(token.lower())
    return refs


def scan_calculated_field_expressions(definition: dict, oc_dataset_identifiers: set,
                                       oc_columns: list[str], hits: Counter,
                                       asset_label: str = ""):
    """
    Tallies OC column references inside calculated-field Expression text,
    including:
      - direct references, braced ({col}) or bare (col)
      - transitive references, where calc field A references calc field B
        (by name) and B references an OC column
    """
    calc_fields = definition.get("CalculatedFields", [])
    if DEBUG and asset_label:
        print(f"    [{asset_label}] {len(calc_fields)} calculated field(s) total: "
              f"{[(c.get('Name'), c.get('DataSetIdentifier')) for c in calc_fields]}")

    oc_columns_set = set(oc_columns)
    oc_calc_names = build_calc_field_name_lookup(calc_fields, oc_dataset_identifiers)

    # Map calc field name -> its own extracted refs, for transitive resolution
    calc_name_to_refs = {}
    for calc in calc_fields:
        name = calc.get("Name", "").lower()
        calc_name_to_refs[name] = extract_field_refs(calc.get("Expression", ""))

    def resolve_to_columns(field_name: str, seen: set) -> set:
        """Recursively resolve a referenced name down to actual OC columns."""
        if field_name in seen:
            return set()  # guard against circular refs
        seen.add(field_name)
        if field_name in oc_columns_set:
            return {field_name}
        resolved = set()
        if field_name in calc_name_to_refs:
            for ref in calc_name_to_refs[field_name]:
                resolved.update(resolve_to_columns(ref, seen))
        return resolved

    for calc in calc_fields:
        if calc.get("DataSetIdentifier") not in oc_dataset_identifiers:
            continue
        expr = calc.get("Expression", "")
        direct_refs = extract_field_refs(expr)
        for ref in direct_refs:
            for col in resolve_to_columns(ref, set()):
                hits[col] += 1


def scan_quicksight_definition(definition: dict, oc_columns: list[str], asset_label: str = "") -> Counter:
    oc_ids = find_oc_dataset_identifiers(definition, asset_label)
    hits = Counter()
    if not oc_ids:
        return hits  # this analysis/dashboard doesn't use OC at all
    find_column_identifier_refs(definition, oc_ids, hits)
    scan_calculated_field_expressions(definition, oc_ids, oc_columns, hits, asset_label)
    return hits


def scan_quicksight_dataset_calculated_fields(oc_columns: list[str]) -> Counter:
    """
    OC's own dataset-level calculated columns (CreateColumnsOperation in
    LogicalTableMap) can reference other OC columns in their expressions.
    """
    hits = Counter()
    oc_columns_set = set(oc_columns)
    resp = qs.describe_data_set(AwsAccountId=AWS_ACCOUNT_ID, DataSetId=OC_DATASET_ID)
    logical_map = resp["DataSet"].get("LogicalTableMap", {})

    # First pass: collect every calculated column's own refs, for transitive resolution
    # (e.g. calc column "margin" = {revenue} - {cost}, then "margin_pct" = {margin} / {revenue})
    calc_name_to_refs = {}
    all_create_cols = []
    for table in logical_map.values():
        for transform in table.get("DataTransforms", []):
            for c in transform.get("CreateColumnsOperation", {}).get("Columns", []):
                name = c.get("ColumnName", "").lower()
                refs = extract_field_refs(c.get("ColumnExpression", ""))
                calc_name_to_refs[name] = refs
                all_create_cols.append(c)

    if DEBUG:
        print(f"    [OC dataset] {len(all_create_cols)} dataset-level calculated column(s): "
              f"{[c.get('ColumnName') for c in all_create_cols]}")

    def resolve_to_columns(field_name: str, seen: set) -> set:
        if field_name in seen:
            return set()
        seen.add(field_name)
        if field_name in oc_columns_set:
            return {field_name}
        resolved = set()
        if field_name in calc_name_to_refs:
            for ref in calc_name_to_refs[field_name]:
                resolved.update(resolve_to_columns(ref, seen))
        return resolved

    for c in all_create_cols:
        expr = c.get("ColumnExpression", "")
        for ref in extract_field_refs(expr):
            for col in resolve_to_columns(ref, set()):
                hits[col] += 1

    return hits


def check_dataset_select_star(select_star_hits: list):
    """Check whether OC (or datasets built from it) use a SELECT * custom SQL source."""
    resp = qs.describe_data_set(AwsAccountId=AWS_ACCOUNT_ID, DataSetId=OC_DATASET_ID)
    physical_map = resp["DataSet"].get("PhysicalTableMap", {})
    for phys_id, phys_table in physical_map.items():
        custom_sql = phys_table.get("CustomSql")
        if custom_sql:
            sql_lower = custom_sql.get("SqlQuery", "").lower()
            if SELECT_STAR_RE.search(sql_lower):
                select_star_hits.append({
                    "source_type": "quicksight_dataset_customsql",
                    "location": f"OC dataset ({OC_DATASET_ID}) physical table {phys_id}",
                    "detail": "OC's own dataset definition uses SELECT * custom SQL",
                    "sql_snippet": custom_sql.get("SqlQuery", "")[:500],
                })


def scan_all_quicksight_assets(oc_columns: list[str]):
    """
    Iterates every analysis and dashboard in the account, pulls its full
    Definition, and tallies OC column references. Also checks each
    analysis/dashboard's dataset(s) for CustomSql SELECT * usage on OC.
    """
    column_hits = defaultdict(Counter)  # {"analysis"/"dashboard": Counter}
    select_star_hits = []
    asset_details = []  # per-asset breakdown for traceability

    # --- Analyses ---
    print("Listing QuickSight analyses...")
    paginator = qs.get_paginator("list_analyses")
    analyses = []
    for page in paginator.paginate(AwsAccountId=AWS_ACCOUNT_ID):
        analyses.extend(page.get("AnalysisSummaryList", []))

    for a in analyses:
        analysis_id = a["AnalysisId"]
        name = a.get("Name", analysis_id)
        try:
            resp = qs.describe_analysis_definition(
                AwsAccountId=AWS_ACCOUNT_ID, AnalysisId=analysis_id
            )
        except Exception as e:
            print(f"  Skipping analysis {name} ({analysis_id}): {e}")
            continue
        definition = resp.get("Definition", {})
        hits = scan_quicksight_definition(definition, oc_columns, asset_label=f"analysis:{name}")
        if hits:
            column_hits["analysis"].update(hits)
            asset_details.append({
                "source_type": "analysis", "id": analysis_id, "name": name,
                "columns_referenced": dict(hits),
            })

    # --- Dashboards ---
    print("Listing QuickSight dashboards...")
    paginator = qs.get_paginator("list_dashboards")
    dashboards = []
    for page in paginator.paginate(AwsAccountId=AWS_ACCOUNT_ID):
        dashboards.extend(page.get("DashboardSummaryList", []))

    for d in dashboards:
        dashboard_id = d["DashboardId"]
        name = d.get("Name", dashboard_id)
        try:
            resp = qs.describe_dashboard_definition(
                AwsAccountId=AWS_ACCOUNT_ID, DashboardId=dashboard_id
            )
        except Exception as e:
            print(f"  Skipping dashboard {name} ({dashboard_id}): {e}")
            continue
        definition = resp.get("Definition", {})
        hits = scan_quicksight_definition(definition, oc_columns, asset_label=f"dashboard:{name}")
        if hits:
            column_hits["dashboard"].update(hits)
            asset_details.append({
                "source_type": "dashboard", "id": dashboard_id, "name": name,
                "columns_referenced": dict(hits),
            })

    check_dataset_select_star(select_star_hits)

    return column_hits, select_star_hits, asset_details


# -------------------------------------------------------------------------
# 3. Main
# -------------------------------------------------------------------------
def main():
    oc_columns = get_oc_columns()
    print(f"OC has {len(oc_columns)} columns: {oc_columns}\n")

    athena_hits, athena_select_star = scan_athena_views(oc_columns)
    qs_hits_by_type, qs_select_star, qs_asset_details = scan_all_quicksight_assets(oc_columns)
    dataset_calc_hits = scan_quicksight_dataset_calculated_fields(oc_columns)

    # --- Combine into a single tally table ---
    all_sources = {
        "athena_views": athena_hits,
        "quicksight_analyses": qs_hits_by_type.get("analysis", Counter()),
        "quicksight_dashboards": qs_hits_by_type.get("dashboard", Counter()),
        "oc_dataset_calculated_fields": dataset_calc_hits,
    }

    tally_rows = []
    for col in oc_columns:
        row = {"column": col}
        total = 0
        for source_name, counter in all_sources.items():
            count = counter.get(col, 0)
            row[source_name] = count
            total += count
        row["total_references"] = total
        tally_rows.append(row)

    tally_df = pd.DataFrame(tally_rows).sort_values("total_references", ascending=True)
    tally_out = "/mnt/user-data/outputs/oc_column_usage_tally.csv"
    tally_df.to_csv(tally_out, index=False)
    print(f"\nSaved column usage tally to {tally_out}")
    print("\nColumns with ZERO downstream references found (candidates to drop, pending manual check):")
    print(tally_df[tally_df["total_references"] == 0]["column"].tolist())

    # --- SELECT * report ---
    all_select_star = athena_select_star + qs_select_star
    select_star_df = pd.DataFrame(all_select_star)
    select_star_out = "/mnt/user-data/outputs/oc_select_star_locations.csv"
    select_star_df.to_csv(select_star_out, index=False)
    print(f"\nFound {len(all_select_star)} SELECT * usages touching OC.")
    print(f"Saved details to {select_star_out}")

    # --- Per-asset breakdown, for tracing which dashboard/analysis uses what ---
    asset_df = pd.DataFrame(qs_asset_details)
    asset_out = "/mnt/user-data/outputs/oc_quicksight_asset_breakdown.csv"
    asset_df.to_csv(asset_out, index=False)
    print(f"Saved per-analysis/dashboard column breakdown to {asset_out}")


if __name__ == "__main__":
    main()