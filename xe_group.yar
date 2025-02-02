import "hash"

rule XE_Group_webshell_V1 {
    meta:
        author = "Intezer Labs"
        description = "Detect WebShell from XE Group attacks in 2020"
        date = "13-12-2024"
        version = "1.0"
        hash = "680b7e8ec8204975c5026bcbaf70f7e9620eacdd7bf72e5476d17266b4a7d316"
        reference = "https://intezer.com/blog/research/xe-group-exploiting-zero-days/"

    strings:

        $w_1 = "<%@ Page Language=\"C#" 
        $w_2 = "EnableViewState=\"true\"%>" 
        $w_3 = "<script runat=\"server\">"      

        $pageload_function = "protected void Page_load(" ascii

        // unique strings
        $s1 = "sqlCommandQuery" ascii
        $s2 = "ismatchagent" ascii
        $s3 = "IsServerConnected" ascii
        $s4 = "DATABASE=master;connect timeout=10;" ascii
        $s5 = "WGVUaGFuaHxYZUdyb3Vwcw==" ascii
        $s6 = "\"Success Connection\";" ascii
        $s7 = "\"You sure scan all connect on this server?\"" ascii
        $s8 = "Please enter connect string. Server address of connect string must valid IP!" ascii

        //unique SQL queries
        $q1 = "RECONFIGURE;EXEC sp_configure 'show advanced options', 1;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE;" ascii
        $q2 = "SELECT o.NAME, i.rowcnt FROM sysindexes AS i INNER JOIN sysobjects AS o ON i.id = o.id WHERE i.indid < 2  AND i.rowcnt > 0 AND OBJECTPROPERTY(o.id, 'IsMSShipped') = 0 ORDER BY i.rowcnt DESC" ascii
        $q3 = "SELECT name,crdate,filename FROM master.dbo.sysdatabases" ascii
        $q4 = "SELECT TOP 100 * FROM [XXXXX] ORDER BY 1 DESC" ascii

    condition:
        2 of ($w_*) //detect ASPX webshell
        and
        $pageload_function
        and
        (
            1 of ($s*)
            or
            1 of ($q*)
        )
}

rule XE_Group_webshell_V2 {
    meta:
        author = "Intezer Labs"
        description = "Detect WebShell from XE Group attacks in 2024"
        date = "13-12-2024"
        version = "2.0"
        hash = "38b2d52dc471587fb65ef99c64cb3f69470ddfdaa184a256aecb26edeff3553a"
        reference = "https://intezer.com/blog/research/xe-group-exploiting-zero-days/"

    strings:

        $w_1 = "<%@ Page Language=\"C"
        $w_2 = "EnableViewState=\"false\""
        $w_3 = "<%@ Import Namespace=\"System.IO\""
        $w_4 = "<script runat=\"server\">"      

        $s_1 = "\"You sure scan all sharing IP on this server?\"" ascii
        $s_2 = "Request.QueryString[\"switchtabdata\"] == \"2\"" ascii
        $s_3 = "t.innerHTML = \"Scaning [\" + l + \"]...\";" ascii
        $s_4 = "Request.QueryString[\"rmdir\"]" ascii
        $s_5 = "(!string.IsNullOrEmpty(Request\"rawexport\"]))" ascii
        $s_6 = "aHR0cHM6Ly9oaXZuZC5jb20vc29mdHdhcmUvN3ouZXhl" ascii  //https://hivnd.com/software/7z[.]exe"
        $s_7 = "VE1Ub2RheQ==" ascii // TMToday"
        $s_8 = "IPServer = Request.ServerVariables[\"REMOTE_ADDR\"];" ascii
        $s_9 = "(Process|GetFiles|GetDirectories|WriteAllText|SaveAs|ExecuteReader)" ascii
        $s_10 = "\"You sure scan all sharing IP on this server?\"" ascii
        $s_11 = "\"command=net%20view%20\"" ascii
        $s_12 = "\"Scaning [\"" ascii

        $unique_function_name = "bool ismatchagent" ascii

        $pageload_function = "void Page_Load(object sender, EventArgs e)" ascii

        $function_name_1 = "string uriDecode" ascii
        $function_name_2 = "string tranpathdir" ascii
        $function_name_3 = "void sendcommand" ascii
        $function_name_4 = "string hts" ascii
        $function_name_5 = "string sth" ascii
        $function_name_6 = "String GetIPAddress" ascii
        $function_name_7 = "string HasWritePermissionOnDir" ascii
        $function_name_8 = "void SQLSlient" ascii
        $function_name_9 = "void btnExecute" ascii
        $function_name_10 = "string regReplace" ascii
        $function_name_11 = "void doScanner" ascii
        $function_name_12 = "bool stringInStr" ascii
        $function_name_14 = "void dlServFiles" ascii
        $function_name_15 = "string stringMid" ascii
        $function_name_16 = "string ByteArrayToHexString" ascii
        $function_name_17 = "string IsServerConnected" ascii
        
        //"netstat -a"
        $v_1 = "&#110;&#101;&#116;&#115;&#116;&#97;&#116;&#32;&#45;&#97;"
        //findstr /spin /c:"xxxxxx;" "D:\*.asp
        $v_2 = "&#102;&#105;&#110;&#100;&#115;&#116;&#114;&#32;&#47;&#115;&#112;&#105;&#110;&#32;&#47;&#99;&#58;&#34;&#120;&#120;&#120;&#120;&#120;&#120;&#59;&#34;&#32;&#34;&#68;&#58;&#92;&#42;&#46;&#97;&#115;&#112;&#34;"
        //"for /L %h IN (1,1,255) DO net view 192.168.0.%h >> C:\ProgramData\NetShare.tmp"
        $v_3 = "&#102;&#111;&#114;&#32;&#47;&#76;&#32;&#37;&#104;&#32;&#73;&#78;&#32;&#40;&#49;&#44;&#49;&#44;&#50;&#53;&#53;&#41;&#32;&#68;&#79;&#32;&#110;&#101;&#116;&#32;&#118;&#105;&#101;&#119;&#32;&#49;&#57;&#50;&#46;&#49;&#54;&#56;&#46;&#48;&#46;&#37;&#104;&#32;&#62;&#62;&#32;&#67;&#58;&#92;&#80;&#114;&#111;&#103;&#114;&#97;&#109;&#68;&#97;&#116;&#97;&#92;&#78;&#101;&#116;&#83;&#104;&#97;&#114;&#101;&#46;&#116;&#109;&#112;"
        //"ATTRIB +H +S"
        $v_4 = "&#65;&#84;&#84;&#82;&#73;&#66;&#32;&#43;&#72;&#32;&#43;&#83;"
        //"type %APP_POOL_CONFIG%"
        $v_5 = "&#116;&#121;&#112;&#101;&#32;&#37;&#65;&#80;&#80;&#95;&#80;&#79;&#79;&#76;&#95;&#67;&#79;&#78;&#70;&#73;&#71;&#37;"
        //"takeown /F xxxx.xxx /A /R /D Y"
        $v_6 = "&#116;&#97;&#107;&#101;&#111;&#119;&#110;&#32;&#47;&#70;&#32;&#120;&#120;&#120;&#120;&#46;&#120;&#120;&#120;&#32;&#47;&#65;&#32;&#47;&#82;&#32;&#47;&#68;&#32;&#89;"
        //"icacls C:\inetpub /remove:d Everyone /grant:r Everyone:(OI)(CI)F /T"
        $v_7 = "&#105;&#99;&#97;&#99;&#108;&#115;&#32;&#67;&#58;&#92;&#105;&#110;&#101;&#116;&#112;&#117;&#98;&#32;&#47;&#114;&#101;&#109;&#111;&#118;&#101;&#58;&#100;&#32;&#69;&#118;&#101;&#114;&#121;&#111;&#110;&#101;&#32;&#47;&#103;&#114;&#97;&#110;&#116;&#58;&#114;&#32;&#69;&#118;&#101;&#114;&#121;&#111;&#110;&#101;&#58;&#40;&#79;&#73;&#41;&#40;&#67;&#73;&#41;&#70;&#32;&#47;&#84;"
        //"icacls xxxx.xxx /setowner %USERNAME% /T /C"
        $v_8 = "&#105;&#99;&#97;&#99;&#108;&#115;&#32;&#120;&#120;&#120;&#120;&#46;&#120;&#120;&#120;&#32;&#47;&#115;&#101;&#116;&#111;&#119;&#110;&#101;&#114;&#32;&#37;&#85;&#83;&#69;&#82;&#78;&#65;&#77;&#69;&#37;&#32;&#47;&#84;&#32;&#47;&#67;"
        //"PowerShell (Get-Item "xxxxxxxxxxxx").LastWriteTime=("01 Jan 2018 00:00:00")"
        $v_9 = "&#80;&#111;&#119;&#101;&#114;&#83;&#104;&#101;&#108;&#108;&#32;&#40;&#71;&#101;&#116;&#45;&#73;&#116;&#101;&#109;&#32;&#34;&#120;&#120;&#120;&#120;&#120;&#120;&#120;&#120;&#120;&#120;&#120;&#120;&#34;&#41;&#46;&#76;&#97;&#115;&#116;&#87;&#114;&#105;&#116;&#101;&#84;&#105;&#109;&#101;&#61;&#40;&#34;&#48;&#49;&#32;&#74;&#97;&#110;&#32;&#50;&#48;&#49;&#56;&#32;&#48;&#48;&#58;&#48;&#48;&#58;&#48;&#48;&#34;&#41;"
        //"PowerShell Import-Module .\xxxxx.ps1"
        $v_10 = "&#80;&#111;&#119;&#101;&#114;&#83;&#104;&#101;&#108;&#108;&#32;&#73;&#109;&#112;&#111;&#114;&#116;&#45;&#77;&#111;&#100;&#117;&#108;&#101;&#32;&#46;&#92;&#120;&#120;&#120;&#120;&#120;&#46;&#112;&#115;&#49;"
        //"\" selected>-- Quick Command --"
        $v_11 = "\" selected>&#45;&#45;&#32;&#81;&#117;&#105;&#99;&#107;&#32;&#67;&#111;&#109;&#109;&#97;&#110;&#100;&#32;&#45;&#45;"
        //"SELECT name&comma;crdate&comma;filename FROM master&period;dbo&period;sysdatabases\">Show All Database Name"
	    $v_12 = "&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#110;&#97;&#109;&#101;&comma;&#99;&#114;&#100;&#97;&#116;&#101;&comma;&#102;&#105;&#108;&#101;&#110;&#97;&#109;&#101;&#32;&#70;&#82;&#79;&#77;&#32;&#109;&#97;&#115;&#116;&#101;&#114;&period;&#100;&#98;&#111;&period;&#115;&#121;&#115;&#100;&#97;&#116;&#97;&#98;&#97;&#115;&#101;&#115;\">&#83;&#104;&#111;&#119;&#32;&#65;&#108;&#108;&#32;&#68;&#97;&#116;&#97;&#98;&#97;&#115;&#101;&#32;&#78;&#97;&#109;&#101;"
        // "SELECT o&period;NAME&comma; i&period;rowcnt FROM sysindexes AS i INNER JOIN sysobjects AS o ON i&period;id &equals; o&period;id WHERE i&period;indid < 2  AND i&period;rowcnt > 0 AND OBJECTPROPERTY&lpar;o&period;id&comma; 'IsMSShipped'&rpar; &equals; 0 ORDER BY i&period;rowcnt DESC\">Show All Tables With Count"
	    $v_13 = "&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#111;&period;&#78;&#65;&#77;&#69;&comma;&#32;&#105;&period;&#114;&#111;&#119;&#99;&#110;&#116;&#32;&#70;&#82;&#79;&#77;&#32;&#115;&#121;&#115;&#105;&#110;&#100;&#101;&#120;&#101;&#115;&#32;&#65;&#83;&#32;&#105;&#32;&#73;&#78;&#78;&#69;&#82;&#32;&#74;&#79;&#73;&#78;&#32;&#115;&#121;&#115;&#111;&#98;&#106;&#101;&#99;&#116;&#115;&#32;&#65;&#83;&#32;&#111;&#32;&#79;&#78;&#32;&#105;&period;&#105;&#100;&#32;&equals;&#32;&#111;&period;&#105;&#100;&#32;&#87;&#72;&#69;&#82;&#69;&#32;&#105;&period;&#105;&#110;&#100;&#105;&#100;&#32;&lt;&#32;&#50;&#32;&#32;&#65;&#78;&#68;&#32;&#105;&period;&#114;&#111;&#119;&#99;&#110;&#116;&#32;&gt;&#32;&#48;&#32;&#65;&#78;&#68;&#32;&#79;&#66;&#74;&#69;&#67;&#84;&#80;&#82;&#79;&#80;&#69;&#82;&#84;&#89;&lpar;&#111;&period;&#105;&#100;&comma;&#32;&apos;&#73;&#115;&#77;&#83;&#83;&#104;&#105;&#112;&#112;&#101;&#100;&apos;&rpar;&#32;&equals;&#32;&#48;&#32;&#79;&#82;&#68;&#69;&#82;&#32;&#66;&#89;&#32;&#105;&period;&#114;&#111;&#119;&#99;&#110;&#116;&#32;&#68;&#69;&#83;&#67;\">&#83;&#104;&#111;&#119;&#32;&#65;&#108;&#108;&#32;&#84;&#97;&#98;&#108;&#101;&#115;&#32;&#87;&#105;&#116;&#104;&#32;&#67;&#111;&#117;&#110;&#116;"
        //$v_14 = "SELECT sc&period;name &plus;'&period;'&plus; ta&period;name TableName&comma; SUM&lpar;pa&period;rows&rpar; RowCnt FROM sys&period;tables ta INNER JOIN sys&period;partitions pa ON pa&period;OBJECT&lowbar;ID &equals; ta&period;OBJECT&lowbar;ID INNER JOIN sys&period;schemas sc ON ta&period;schema&lowbar;id &equals; sc&period;schema&lowbar;id WHERE ta&period;is&lowbar;ms&lowbar;shipped &equals; 0 AND pa&period;index&lowbar;id IN &lpar;1&comma;0&rpar; GROUP BY sc&period;name&comma;ta&period;name ORDER BY SUM&lpar;pa&period;rows&rpar; DESC\">Count Tables Row (Declined sysobject)"
	    $v_14 = "&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#115;&#99;&period;&#110;&#97;&#109;&#101;&#32;&plus;&apos;&period;&apos;&plus;&#32;&#116;&#97;&period;&#110;&#97;&#109;&#101;&#32;&#84;&#97;&#98;&#108;&#101;&#78;&#97;&#109;&#101;&comma;&#32;&#83;&#85;&#77;&lpar;&#112;&#97;&period;&#114;&#111;&#119;&#115;&rpar;&#32;&#82;&#111;&#119;&#67;&#110;&#116;&#32;&#70;&#82;&#79;&#77;&#32;&#115;&#121;&#115;&period;&#116;&#97;&#98;&#108;&#101;&#115;&#32;&#116;&#97;&#32;&#73;&#78;&#78;&#69;&#82;&#32;&#74;&#79;&#73;&#78;&#32;&#115;&#121;&#115;&period;&#112;&#97;&#114;&#116;&#105;&#116;&#105;&#111;&#110;&#115;&#32;&#112;&#97;&#32;&#79;&#78;&#32;&#112;&#97;&period;&#79;&#66;&#74;&#69;&#67;&#84;&lowbar;&#73;&#68;&#32;&equals;&#32;&#116;&#97;&period;&#79;&#66;&#74;&#69;&#67;&#84;&lowbar;&#73;&#68;&#32;&#73;&#78;&#78;&#69;&#82;&#32;&#74;&#79;&#73;&#78;&#32;&#115;&#121;&#115;&period;&#115;&#99;&#104;&#101;&#109;&#97;&#115;&#32;&#115;&#99;&#32;&#79;&#78;&#32;&#116;&#97;&period;&#115;&#99;&#104;&#101;&#109;&#97;&lowbar;&#105;&#100;&#32;&equals;&#32;&#115;&#99;&period;&#115;&#99;&#104;&#101;&#109;&#97;&lowbar;&#105;&#100;&#32;&#87;&#72;&#69;&#82;&#69;&#32;&#116;&#97;&period;&#105;&#115;&lowbar;&#109;&#115;&lowbar;&#115;&#104;&#105;&#112;&#112;&#101;&#100;&#32;&equals;&#32;&#48;&#32;&#65;&#78;&#68;&#32;&#112;&#97;&period;&#105;&#110;&#100;&#101;&#120;&lowbar;&#105;&#100;&#32;&#73;&#78;&#32;&lpar;&#49;&comma;&#48;&rpar;&#32;&#71;&#82;&#79;&#85;&#80;&#32;&#66;&#89;&#32;&#115;&#99;&period;&#110;&#97;&#109;&#101;&comma;&#116;&#97;&period;&#110;&#97;&#109;&#101;&#32;&#79;&#82;&#68;&#69;&#82;&#32;&#66;&#89;&#32;&#83;&#85;&#77;&lpar;&#112;&#97;&period;&#114;&#111;&#119;&#115;&rpar;&#32;&#68;&#69;&#83;&#67;\">&#67;&#111;&#117;&#110;&#116;&#32;&#84;&#97;&#98;&#108;&#101;&#115;&#32;&#82;&#111;&#119;&#32;&#40;&#68;&#101;&#99;&#108;&#105;&#110;&#101;&#100;&#32;&#115;&#121;&#115;&#111;&#98;&#106;&#101;&#99;&#116;&#41;"
        //"SELECT o&period;NAME&comma; i&period;rowcnt  FROM sysindexes AS i  INNER JOIN sysobjects AS o ON i&period;id &equals; o&period;id  INNER JOIN syscolumns AS c ON c&period;id &equals; o&period;id  WHERE i&period;indid < 2 AND i&period;rowcnt > 0 AND OBJECTPROPERTY&lpar;o&period;id&comma; 'IsMSShipped'&rpar; &equals; 0 AND c&period;name LIKE '&percnt;pass&percnt;' ORDER BY i&period;rowcnt DESC&semi;\">Find Table Name Like Column Name"
	    $v_15 = "&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#111;&period;&#78;&#65;&#77;&#69;&comma;&#32;&#105;&period;&#114;&#111;&#119;&#99;&#110;&#116;&#32;&#32;&#70;&#82;&#79;&#77;&#32;&#115;&#121;&#115;&#105;&#110;&#100;&#101;&#120;&#101;&#115;&#32;&#65;&#83;&#32;&#105;&#32;&#32;&#73;&#78;&#78;&#69;&#82;&#32;&#74;&#79;&#73;&#78;&#32;&#115;&#121;&#115;&#111;&#98;&#106;&#101;&#99;&#116;&#115;&#32;&#65;&#83;&#32;&#111;&#32;&#79;&#78;&#32;&#105;&period;&#105;&#100;&#32;&equals;&#32;&#111;&period;&#105;&#100;&#32;&#32;&#73;&#78;&#78;&#69;&#82;&#32;&#74;&#79;&#73;&#78;&#32;&#115;&#121;&#115;&#99;&#111;&#108;&#117;&#109;&#110;&#115;&#32;&#65;&#83;&#32;&#99;&#32;&#79;&#78;&#32;&#99;&period;&#105;&#100;&#32;&equals;&#32;&#111;&period;&#105;&#100;&#32;&#32;&#87;&#72;&#69;&#82;&#69;&#32;&#105;&period;&#105;&#110;&#100;&#105;&#100;&#32;&lt;&#32;&#50;&#32;&#65;&#78;&#68;&#32;&#105;&period;&#114;&#111;&#119;&#99;&#110;&#116;&#32;&gt;&#32;&#48;&#32;&#65;&#78;&#68;&#32;&#79;&#66;&#74;&#69;&#67;&#84;&#80;&#82;&#79;&#80;&#69;&#82;&#84;&#89;&lpar;&#111;&period;&#105;&#100;&comma;&#32;&apos;&#73;&#115;&#77;&#83;&#83;&#104;&#105;&#112;&#112;&#101;&#100;&apos;&rpar;&#32;&equals;&#32;&#48;&#32;&#65;&#78;&#68;&#32;&#99;&period;&#110;&#97;&#109;&#101;&#32;&#76;&#73;&#75;&#69;&#32;&apos;&percnt;&#112;&#97;&#115;&#115;&percnt;&apos;&#32;&#79;&#82;&#68;&#69;&#82;&#32;&#66;&#89;&#32;&#105;&period;&#114;&#111;&#119;&#99;&#110;&#116;&#32;&#68;&#69;&#83;&#67;&semi;\">&#70;&#105;&#110;&#100;&#32;&#84;&#97;&#98;&#108;&#101;&#32;&#78;&#97;&#109;&#101;&#32;&#76;&#105;&#107;&#101;&#32;&#67;&#111;&#108;&#117;&#109;&#110;&#32;&#78;&#97;&#109;&#101;"
        //"RECONFIGURE&semi;EXEC sp&lowbar;configure 'show advanced options'&comma; 1&semi;EXEC sp&lowbar;configure 'xp&lowbar;cmdshell'&comma; 1&semi;RECONFIGURE&semi;\">Enable XP_CMDSHELL"
	    $v_16 = "&#82;&#69;&#67;&#79;&#78;&#70;&#73;&#71;&#85;&#82;&#69;&semi;&#69;&#88;&#69;&#67;&#32;&#115;&#112;&lowbar;&#99;&#111;&#110;&#102;&#105;&#103;&#117;&#114;&#101;&#32;&apos;&#115;&#104;&#111;&#119;&#32;&#97;&#100;&#118;&#97;&#110;&#99;&#101;&#100;&#32;&#111;&#112;&#116;&#105;&#111;&#110;&#115;&apos;&comma;&#32;&#49;&semi;&#69;&#88;&#69;&#67;&#32;&#115;&#112;&lowbar;&#99;&#111;&#110;&#102;&#105;&#103;&#117;&#114;&#101;&#32;&apos;&#120;&#112;&lowbar;&#99;&#109;&#100;&#115;&#104;&#101;&#108;&#108;&apos;&comma;&#32;&#49;&semi;&#82;&#69;&#67;&#79;&#78;&#70;&#73;&#71;&#85;&#82;&#69;&semi;\">&#69;&#110;&#97;&#98;&#108;&#101;&#32;&#88;&#80;&#95;&#67;&#77;&#68;&#83;&#72;&#69;&#76;&#76;"
        //"EXEC xp&lowbar;cmdshell 'wmic logicaldisk get name&comma;description'\">Execute SQL Command Shell"
	    $v_17 = "&#69;&#88;&#69;&#67;&#32;&#120;&#112;&lowbar;&#99;&#109;&#100;&#115;&#104;&#101;&#108;&#108;&#32;&apos;&#119;&#109;&#105;&#99;&#32;&#108;&#111;&#103;&#105;&#99;&#97;&#108;&#100;&#105;&#115;&#107;&#32;&#103;&#101;&#116;&#32;&#110;&#97;&#109;&#101;&comma;&#100;&#101;&#115;&#99;&#114;&#105;&#112;&#116;&#105;&#111;&#110;&apos;\">&#69;&#120;&#101;&#99;&#117;&#116;&#101;&#32;&#83;&#81;&#76;&#32;&#67;&#111;&#109;&#109;&#97;&#110;&#100;&#32;&#83;&#104;&#101;&#108;&#108;"
        //"SELECT TOP 100 &ast; FROM &lsqb;XXXXX&rsqb; ORDER BY 1 DESC\">Show 100 Rows On Tables"
	    $v_18 = "&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#84;&#79;&#80;&#32;&#49;&#48;&#48;&#32;&ast;&#32;&#70;&#82;&#79;&#77;&#32;&lsqb;&#88;&#88;&#88;&#88;&#88;&rsqb;&#32;&#79;&#82;&#68;&#69;&#82;&#32;&#66;&#89;&#32;&#49;&#32;&#68;&#69;&#83;&#67;\">&#83;&#104;&#111;&#119;&#32;&#49;&#48;&#48;&#32;&#82;&#111;&#119;&#115;&#32;&#79;&#110;&#32;&#84;&#97;&#98;&#108;&#101;&#115;"
        //"SELECT name,crdate,filename FROM master.dbo.sysdatabases" 
        $v_19 = "&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#110;&#97;&#109;&#101;,&#99;&#114;&#100;&#97;&#116;&#101;,&#102;&#105;&#108;&#101;&#110;&#97;&#109;&#101;&#32;&#70;&#82;&#79;&#77;&#32;&#109;&#97;&#115;&#116;&#101;&#114;.&#100;&#98;&#111;.&#115;&#121;&#115;&#100;&#97;&#116;&#97;&#98;&#97;&#115;&#101;&#115;" 
        //"Please enter connect string. Server address of connect string must valid IP!"
        $v_20 = "&#80;&#108;&#101;&#97;&#115;&#101;&#32;&#101;&#110;&#116;&#101;&#114;&#32;&#99;&#111;&#110;&#110;&#101;&#99;&#116;&#32;&#115;&#116;&#114;&#105;&#110;&#103;&#46;&#32;&#83;&#101;&#114;&#118;&#101;&#114;&#32;&#97;&#100;&#100;&#114;&#101;&#115;&#115;&#32;&#111;&#102;&#32;&#99;&#111;&#110;&#110;&#101;&#99;&#116;&#32;&#115;&#116;&#114;&#105;&#110;&#103;&#32;&#109;&#117;&#115;&#116;&#32;&#118;&#97;&#108;&#105;&#100;&#32;&#73;&#80;&#33;"
        //"Query Data><option value=\"1\">Export Data"
        $v_21 = "&#81;&#117;&#101;&#114;&#121;&#32;&#68;&#97;&#116;&#97;><option value=\"1\">&#69;&#120;&#112;&#111;&#114;&#116;&#32;&#68;&#97;&#116;&#97;"

    condition:

        (
            hash.md5(0, filesize) == "7abb73b7844f2308d9c62954e6e8b7fc"
            or
            hash.md5(0, filesize) == "7a9b5c3bb7dab0857ee2c2d71758eca3"
            or
            hash.md5(0, filesize) == "457d7e3a708d1b5c6a8d449e52064985"
            or
            hash.md5(0, filesize) == "7a9b5c3bb7dab0857ee2c2d71758eca3"
        )
        or
        (
            2 of ($w_*) //detect ASPX webshell
            and
            $pageload_function
            and
            (
                2 of ($v_*)
                or
                2 of ($function_name_*)
                or
                $unique_function_name
                or 
                any of ($s*)
            )
        )
}
