# V10 Combined VAPT Intelligence Report

## Purpose

This stage reads the outputs produced by:

1. Smart Recon V8.5.1
2. Asset Validation and Normalization V9
3. Technology and Service Intelligence V9.2

It then creates one self-contained Markdown report inside the latest matching run folder:

`combined_vapt_intelligence_report.md`

The script does not rerun scanners and does not modify collected evidence.

## Run

```cmd
run-v10-combined-report.cmd hiapp.pk
```

For a custom recon root:

```cmd
run-v10-combined-report.cmd hiapp.pk E:\path\to\recon_runs
```

Direct Python command:

```cmd
python vapt_combined_report_v10.py --target hiapp.pk --latest-root .\recon_runs --overwrite
```

## Full sequence

```cmd
run-max-v8.5.1-recursive.cmd hiapp.pk
run-v9-normalize.cmd hiapp.pk
run-v9.2-tech-max.cmd hiapp.pk
run-v10-combined-report.cmd hiapp.pk
```

The first three commands collect and structure evidence. The fourth command only reads those results and writes the combined report.
