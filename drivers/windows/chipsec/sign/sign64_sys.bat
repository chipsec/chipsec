copy /Y ..\..\..\chipsec\helper\windows\windows_amd64\chipsec_hlpr.sys 
SignTool sign /fdws /t http://timestamp.digicert.com   chipsec_hlpr.sys
