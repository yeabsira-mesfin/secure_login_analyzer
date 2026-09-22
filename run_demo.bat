@echo off
echo Running Secure Login Analyzer...
python -m src.main data\sample_events.json
echo.
echo Running tests...
python -m unittest discover -s tests -v
pause
