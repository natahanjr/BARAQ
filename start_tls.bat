@echo off
cd /d "F:\My Project\Baraq"
set BARAQ_ENV=production
set BARAQ_TLS=1
set BARAQ_SKIP_SECRET_GEN=1
set BARAQ_TELEMETRY_V2=1
set BARAQ_ALERTS_V2=1
set BARAQ_CORRELATION=1
set BARAQ_RISK=1
set BARAQ_BEHAVIOR_GROUPS=1
rem Cap BLAS/OpenMP threads: background ML retrains otherwise saturate every
rem core and the scheduler cycles balloon (collect/detection 10-40x slower).
set OMP_NUM_THREADS=2
set MKL_NUM_THREADS=2
set OPENBLAS_NUM_THREADS=2
set NUMEXPR_NUM_THREADS=2
"venv\Scripts\python.exe" -m uvicorn backend.main:app --host 0.0.0.0 --port 8443 --ssl-certfile "F:\My Project\Baraq\certs\baraq.crt" --ssl-keyfile "F:\My Project\Baraq\certs\baraq.key"
