@echo off
cd /d C:\Users\HUXYN\Desktop\BruteForceGuard
echo === GIT STATUS ===
git status --short
echo === BACKEND TESTS ===
cd backend
.venv\Scripts\python.exe -m pytest -q 2>&1
echo PYTEST_EXIT=%ERRORLEVEL%
echo === COMPILE ===
.venv\Scripts\python.exe -m compileall app tests 2>&1
echo COMPILE_EXIT=%ERRORLEVEL%
