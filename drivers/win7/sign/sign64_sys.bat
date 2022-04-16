copy /Y ..\..\..\chipsec\helper\win\win7_amd64\chipsec_hlpr.sys 
SignTool sign /s ChipsecCertStore  /t http://timestamp.verisign.com/scripts/timestamp.dll   chipsec_hlpr.sys
