copy /Y ..\..\..\chipsec\helper\win\win7_amd64\chipsec_hlpr.sys 
SignTool sign /fdws /t http://timestamp.digicert.com   chipsec_hlpr.sys
