$ErrorActionPreference = "Stop"
py -3 -m compileall -q .
py -3 -m unittest discover -s tests -v
