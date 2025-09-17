#!/usr/bin/env python3
"""
Terraform (AWS IAM/VPC/S3/EC2/RDS) -> standardized, deterministic JSON.
Robust to python-hcl2 dict-or-list shapes for resource/data entries.

Requires: python-hcl2  (pip install python-hcl2)
"""
import argparse
import io
import json
import os
import re
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Optional, Tuple

import hcl2

# ------------ Service/type mapping ------------
IAM_PREFIX = "aws_iam_"
S3_PREFIX = "aws_s3_"
RDS_PREFIXES = ("aws_rds_", "aws_db_")

VPC_TYPES = {
    "aws_vpc",
    "aws_vpc_dhcp_options",
    "aws_vpc_dhcp_options_association",
    "aws_subnet",
    "aws_route_table",
    "aws_route",
    "aws_main_route_table_association",
    "aws_route_table_association",
    "aws_network_acl",
    "aws_network_acl_rule",
    "aws_internet_gateway",
    "aws_nat_gateway",
    "aws_eip_association",
    "aws_vpc_endpoint",
    "aws_vpc_endpoint_service",
    "aws_vpc_peering_connection",
    "aws_vpc_peering_connection_accepter",
    "aws_flow_log",
    "aws_network_interface",
    "aws_network_interface_sg_attachment",
}

EC2_TYPES = {
    "aws_instance",
    "aws_ami",
    "aws_ami_copy",
    "aws_ami_from_instance",
    "aws_ebs_volume",
    "aws_ebs_snapshot",
    "aws_volume_attachment",
    "aws_snapshot_create_volume_permission",
    "aws_key_pair",
    "aws_launch_template",
    "aws_placement_group",
    "aws_spot_fleet_request",
    "aws_eip",
}

SERVICES_KEYS = ["ec2", "iam", "rds", "s3", "vpc"]  # stable, alphabetical

# Pure interpolation like "${var.foo}" -> {"$expr":"var.foo"}
EXPR_RE = re.compile(r'^\s*\${\s*(?P<inner>[^}]*)\s*}\s*$')


def service_for_type(t: str) -> Optional[str]:
    if t.startswith(IAM_PREFIX):
        return "iam"
    if t.startswith(S3_PREFIX):
        return "s3"
    if t.startswith(RDS_PREFIXES):
        return "rds"
    if t in VPC_TYPES:
        return "vpc"
    if t in EC2_TYPES:
        return "ec2"
    return None


# ------------ Normalization helpers ------------
def normalize_value(v: Any) -> Any:
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0])
        out = OrderedDict()
        for k, val in items:
            if k in ("provisioner", "connection"):
                continue
            out[k] = normalize_value(val)
        return out
    if isinstance(v, list):
        return [normalize_value(x) for x in v]
    if isinstance(v, str):
        m = EXPR_RE.match(v)
        if m:
            inner = m.group("inner").strip()
            return OrderedDict([("$expr", inner)])
        return v
    return v


def _to_expr_or_val(x: Any) -> Any:
    if isinstance(x, str):
        m = EXPR_RE.match(x)
        if m:
            return OrderedDict([("$expr", m.group("inner").strip())])
    return x


def extract_meta(attrs: Dict[str, Any]) -> Tuple[Any, Any, List[str], Optional[str]]:
    count = attrs.pop("count", None)
    for_each = attrs.pop("for_each", None)
    depends_on = attrs.pop("depends_on", None)
    provider = attrs.pop("provider", None)

    count = _to_expr_or_val(count) if count is not None else None
    for_each = _to_expr_or_val(for_each) if for_each is not None else None

    if depends_on is None:
        depends = []
    elif isinstance(depends_on, list):
        depends = [str(x) for x in depends_on]
    else:
        depends = [str(depends_on)]

    provider_alias = None
    if isinstance(provider, str):
        provider_alias = provider

    return count, for_each, depends, provider_alias


def make_record(kind: str, rtype: str, name: str, body: Any) -> Tuple[Optional[OrderedDict], Optional[Tuple[str]]]:
    if not rtype.startswith("aws_"):
        return None, ("non_aws_provider",)
    service = service_for_type(rtype)
    if service is None:
        return None, ("unsupported_service",)
    if not isinstance(body, dict):
        return None, ("malformed_block",)

    attrs = dict(body or {})
    count, for_each, depends_on, provider_alias = extract_meta(attrs)

    if provider_alias and not provider_alias.startswith("aws"):
        return None, ("non_aws_provider_alias",)

    norm_attrs = OrderedDict(sorted((k, normalize_value(v)) for k, v in attrs.items()))
    address = f"{rtype}.{name}"
    rec = OrderedDict()
    rec["address"] = address
    rec["type"] = rtype
    rec["name"] = name
    rec["service"] = service
    rec["mode"] = "data" if kind == "data" else "resource"
    rec["provider_alias"] = provider_alias if provider_alias else None
    rec["depends_on"] = depends_on or []
    rec["count"] = count if count is not None else None
    rec["for_each"] = for_each if for_each is not None else None
    rec["attributes"] = norm_attrs
    return rec, None


def parse_tf_string(content: str) -> Dict[str, Any]:
    if hasattr(hcl2, "loads"):
        return hcl2.loads(content)  # type: ignore[attr-defined]
    return hcl2.load(io.StringIO(content))


def parse_tf_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return hcl2.load(f)


def _iter_resource_entries(section: Any):
    if section is None:
        return
    if isinstance(section, list):
        for entry in section:
            if isinstance(entry, dict):
                for rtype, blocks in entry.items():
                    yield rtype, blocks
    elif isinstance(section, dict):
        for rtype, blocks in section.items():
            yield rtype, blocks


def _iter_name_bodies(blocks: Any):
    if isinstance(blocks, list):
        for block in blocks:
            if isinstance(block, dict):
                for name, body in block.items():
                    yield name, body
    elif isinstance(blocks, dict):
        for name, body in blocks.items():
            yield name, body


def collect_from_doc(doc: Dict[str, Any], include_ignored: bool):
    resources = []
    datas = []
    ignored = []

    for rtype, blocks in _iter_resource_entries(doc.get("resource")):
        if blocks is None:
            continue
        for name, body in _iter_name_bodies(blocks):
            rec, err = make_record("resource", rtype, name, body)
            if rec is not None:
                resources.append(rec)
            elif include_ignored:
                reason = err[0] if err else "unknown"
                ignored.append({"kind": "resource", "type": rtype, "name": str(name), "reason": reason})

    for dtype, blocks in _iter_resource_entries(doc.get("data")):
        if blocks is None:
            continue
        for name, body in _iter_name_bodies(blocks):
            rec, err = make_record("data", dtype, name, body)
            if rec is not None:
                datas.append(rec)
            elif include_ignored:
                reason = err[0] if err else "unknown"
                ignored.append({"kind": "data", "type": dtype, "name": str(name), "reason": reason})

    return resources, datas, ignored


def sort_records(recs):
    return sorted(recs, key=lambda r: (r["type"], r["name"], r["address"]))


def organize_by_service(resources, datas):
    services = {k: {"resources": [], "data_sources": []} for k in SERVICES_KEYS}
    for r in resources:
        services[r["service"]]["resources"].append(r)
    for d in datas:
        services[d["service"]]["data_sources"].append(d)
    for k in SERVICES_KEYS:
        services[k]["resources"] = sort_records(services[k]["resources"])
        services[k]["data_sources"] = sort_records(services[k]["data_sources"])
    return services


def transform_from_prompt(request_obj: Dict[str, Any]) -> Dict[str, Any]:
    files = request_obj.get("files") or []
    options = request_obj.get("options") or {}
    include_ignored = bool(options.get("include_ignored", False))

    all_resources = []
    all_datas = []
    all_ignored = []

    for f in files:
        path = f.get("path") or "<memory>"
        content = f.get("content", "")
        try:
            doc = parse_tf_string(content)
        except Exception as e:
            if include_ignored:
                all_ignored.append({"kind":"file","path":path,"reason":"parse_error","message":str(e)})
            continue
        res, datas, ign = collect_from_doc(doc, include_ignored)
        all_resources.extend(res)
        all_datas.extend(datas)
        all_ignored.extend(ign)

    services = organize_by_service(all_resources, all_datas)
    out = OrderedDict()
    out["version"] = "1.0"
    out["provider"] = "aws"
    out["services"] = OrderedDict((k, services[k]) for k in SERVICES_KEYS)
    if include_ignored:
        all_ignored = sorted(all_ignored, key=lambda x: (x.get("kind",""), x.get("type",""), x.get("name",""), x.get("path",""), x.get("reason","")))
        out["ignored"] = all_ignored
    return out


def gather_tf_files(input_path: str) -> List[str]:
    paths: List[str] = []
    if os.path.isfile(input_path) and input_path.endswith(".tf"):
        paths.append(input_path)
    elif os.path.isdir(input_path):
        for root, _, files in os.walk(input_path):
            for fn in files:
                if fn.endswith(".tf"):
                    paths.append(os.path.join(root, fn))
    return sorted(paths)


def transform_from_path(input_path: str, include_ignored: bool) -> Dict[str, Any]:
    tf_files = gather_tf_files(input_path)
    all_resources = []
    all_datas = []
    all_ignored = []

    for p in tf_files:
        try:
            doc = parse_tf_file(p)
        except Exception as e:
            if include_ignored:
                all_ignored.append({"kind":"file","path":p,"reason":"parse_error","message":str(e)})
            continue
        res, datas, ign = collect_from_doc(doc, include_ignored)
        all_resources.extend(res)
        all_datas.extend(datas)
        all_ignored.extend(ign)

    services = organize_by_service(all_resources, all_datas)
    out = OrderedDict()
    out["version"] = "1.0"
    out["provider"] = "aws"
    out["services"] = OrderedDict((k, services[k]) for k in SERVICES_KEYS)
    if include_ignored:
        all_ignored = sorted(all_ignored, key=lambda x: (x.get("kind",""), x.get("type",""), x.get("name",""), x.get("path",""), x.get("reason","")))
        out["ignored"] = all_ignored
    return out


def main():
    ap = argparse.ArgumentParser(description="Terraform (AWS IAM/VPC/S3/EC2/RDS) -> standardized JSON (deterministic)")
    ap.add_argument("-o", "--output", help="Output JSON file (default: stdout)")
    ap.add_argument("--include-ignored", action="store_true", help="Include ignored items in output")
    ap.add_argument("--from-stdin", action="store_true", help="Read prompt/service JSON from STDIN (overrides path scanning)")
    ap.add_argument("input", nargs="?", help="Path to a .tf file or a directory with .tf files")
    args = ap.parse_args()

    if args.from_stdin:
        try:
            request_obj = json.load(io.TextIOWrapper(io.BufferedReader(os.fdopen(0, 'rb')), encoding="utf-8"))
        except Exception as e:
            raise SystemExit(f"Failed to read JSON from stdin: {e}")
        result = transform_from_prompt(request_obj)
    else:
        if not args.input:
            ap.print_help()
            raise SystemExit(2)
        result = transform_from_path(args.input, args.include_ignored)

    dump = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(dump)
    else:
        print(dump)


if __name__ == "__main__":
    main()
