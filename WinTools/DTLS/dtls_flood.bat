for /l %%x in (1, 1, 100) do (
    pushd %~dp0
    start cmd.exe /c .\dtls_client.bat
    powershell -nop -c "& {sleep -m 100}"
)