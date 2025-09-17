# Terraform → JSON (AWS IAM/VPC/S3/EC2/RDS) — Skeleton Repo (v3)

Script robusto a variaciones de `python-hcl2` (dict vs list) y workflow endurecido.

## Requisitos
```bash
pip install python-hcl2
```

## Ejecución
```bash
python3 scripts/terraform_aws_transformer.py examples/single -o output/terraform.json --include-ignored
```
