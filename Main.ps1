<#
.SYNOPSIS
    Generates security update compliance reports for servers and workstations.
.DESCRIPTION
    V16 - FINAL. The email section is completely customized as per the user's request.
          The email body is now a formatted HTML table summary, and both reports are attached.
#>

[CmdletBinding()]
param(
    # --- Paths and Input Files (Updated for local testing) ---
    [string]$AdComputersCsvPath = ".\Missing_SCCM_Clients\AllForestsComputers.csv",
    [string]$OuExclusionFilePath = ".\Missing_SCCM_Clients\OUs_For_Discovery_Exclusion.txt",
    [string]$ReportOutputPath = ".\Logs\ComplianceReports",

    # --- Active Directory Settings ---
    [string]$ExclusionGroupName = "Excluded_Devices_from_SCCM_Clients_Report",

    # --- Hardcoded OU Exclusions (from original script) ---
    [string[]]$HardcodedExcludedOus = @(
        "company.com/ExtSITE/",
        "company.com/NewComputers", 
        "company.com/DisabledObjects", 
        "company.com/Servers/"
    ),

    # --- SCCM SQL Database Settings ---
    [string]$SccmSqlServer = "SCCM16.company.com",
    [string]$SccmDbName = "CM_P01",

    # --- Report 1: Workstation Settings ---
    [string]$WorkstationCollectionID = "P01006C1",
    [int]$WorkstationSugCiId = 16834489, 

    # --- Report 2: Server Settings ---
    [string]$ServerCollectionID = "P0100690",
    [int]$ServerSugCiId = 16887888,

    # --- Email Toggle ---
    [bool]$SendEmail = $true
)

#=======================================================================================================================
#   Function: Get-FilteredAdComputers
#=======================================================================================================================
function Get-FilteredAdComputers {
    param(
        [Parameter(Mandatory=$true)][string]$CsvPath,
        [Parameter(Mandatory=$true)][string]$ExclusionFilePath,
        [Parameter(Mandatory=$true)][string]$AdExclusionGroup,
        [Parameter(Mandatory=$true)][string[]]$HardcodedOus
    )
    Write-Host "Step 1: Filtering computers from Active Directory export..." -ForegroundColor Green
    $combinedExcludedOus = New-Object System.Collections.Generic.List[string]
    $combinedExcludedOus.AddRange($HardcodedOus)
    try { $combinedExcludedOus.AddRange((Get-Content -LiteralPath $ExclusionFilePath -ErrorAction Stop)) }
    catch { Write-Warning "Could not read OU exclusion file at '$ExclusionFilePath'." }
    try {
        $allAdComputers = Import-Csv -LiteralPath $CsvPath -ErrorAction Stop
        $exclusionGroupMembers = Get-ADGroupMember -Identity $AdExclusionGroup -ErrorAction Stop | Select-Object -ExpandProperty Name
    } catch { Write-Error "Failed to load CSV or AD Group. Error: $($_.Exception.Message)"; return }
    $filteredComputers = New-Object System.Collections.Generic.List[psobject]
    foreach ($computer in $allAdComputers) {
        $isExcluded = $false
        $computerName = $computer.CanonicalName.Split('/')[-1]
        if ([string]::IsNullOrWhiteSpace($computerName)) { continue }
        if ($computer.OSName -notlike "*Windows*") { continue }
        foreach ($excldOU in $combinedExcludedOus) { if ($computer.CanonicalName -like "$excldOU*") { $isExcluded = $true; break } }
        if ($isExcluded) { continue }
        if ($computerName -in $exclusionGroupMembers) { $isExcluded = $true }
        if ($isExcluded) { continue }
        if ($computer.PSObject.Properties['servicePrincipalName'] -and $computer.servicePrincipalName -like "*MSClusterVirtualServer*") { $isExcluded = $true }
        if ($isExcluded) { continue }
        $filteredComputers.Add($computer)
    }
    Write-Host "Found $($filteredComputers.Count) computers in AD after applying all exclusion rules." -ForegroundColor Green
    return $filteredComputers
}

#=======================================================================================================================
#   Function: Get-SccmComplianceData
#=======================================================================================================================
function Get-SccmComplianceData {
    param(
        [string]$SqlServer,
        [string]$Database,
        [string]$CollectionID,
        [int]$SugCiId 
    )
    Write-Host "Step 2: Querying SCCM for compliance data (Collection: $CollectionID)..." -ForegroundColor Cyan
    $sqlQuery = @"
    DECLARE @CollectionID nvarchar(30) = '$CollectionID';
    DECLARE @SUG_CI_ID int = $SugCiId;
    WITH
    DuplicateNames AS (SELECT Netbios_Name0 FROM dbo.v_R_System WHERE Netbios_Name0 IS NOT NULL GROUP BY Netbios_Name0 HAVING COUNT(*) > 1),
    CollectionMembers AS (SELECT fcm.ResourceID FROM dbo.v_FullCollectionMembership fcm WHERE fcm.CollectionID = @CollectionID),
    SUG_Updates AS (SELECT cir.ToCIID AS UpdateCI_ID FROM dbo.v_CIRelation cir WHERE cir.FromCIID = @SUG_CI_ID),
    DeviceComplianceSummary AS (SELECT ucs.ResourceID, COUNT(ucs.CI_ID) AS TotalRelevantUpdates, SUM(CASE WHEN ucs.Status IN (1, 3) THEN 1 ELSE 0 END) AS CompliantUpdates, SUM(CASE WHEN ucs.Status = 2 THEN 1 ELSE 0 END) AS RequiredUpdates FROM dbo.v_UpdateComplianceStatus ucs WHERE ucs.ResourceID IN (SELECT ResourceID FROM CollectionMembers) AND ucs.CI_ID IN (SELECT UpdateCI_ID FROM SUG_Updates) GROUP BY ucs.ResourceID)
    SELECT
      sys.Netbios_Name0 AS [ComputerName], sys.Resource_Domain_OR_Workgr0 AS [Domain], sys.ResourceID, sys.Build01 AS [OSBuild],
      CASE WHEN sys.Client0 IS NULL OR sys.Client0 = 0 THEN N'Client Not Installed' WHEN sys.Active0 = 0 THEN N'Client Inactive' WHEN ISNULL(summary.RequiredUpdates, 0) > 0 THEN N'Non-Compliant' ELSE N'Compliant' END AS [ComplianceStatus],
      ISNULL(summary.RequiredUpdates, 0) AS [RequiredUpdates],
      CAST(ldisk.FreeSpace0 / 1024.0 AS DECIMAL(10, 2)) AS [FreeSpaceC_GB],
      ROUND(COALESCE(csys.TotalPhysicalMemory0, mem.TotalPhysicalMemory0, 0) / (1024.0 * 1024.0), 0) AS [TotalRAM_GB],
      ws.LastHWScan AS [LastHardwareScan],
      CASE WHEN sys.Client0 = 1 THEN N'Yes' ELSE N'No' END AS [IsClientInstalled], 
      CASE WHEN sys.Active0 = 1 THEN N'Yes' ELSE N'No' END AS [IsClientActive],
      CASE WHEN dup.Netbios_Name0 IS NOT NULL THEN N'Yes' ELSE N'No' END AS [IsNameDuplicate]
    FROM CollectionMembers cm
    LEFT JOIN dbo.v_R_System sys ON cm.ResourceID = sys.ResourceID
    LEFT JOIN DeviceComplianceSummary summary ON cm.ResourceID = summary.ResourceID
    LEFT JOIN DuplicateNames dup ON sys.Netbios_Name0 = dup.Netbios_Name0
    LEFT JOIN dbo.v_GS_LOGICAL_DISK ldisk ON sys.ResourceID = ldisk.ResourceID AND ldisk.DeviceID0 = 'C:'
    LEFT JOIN dbo.v_GS_COMPUTER_SYSTEM csys ON sys.ResourceID = csys.ResourceID
    LEFT JOIN dbo.v_GS_X86_PC_MEMORY mem ON sys.ResourceID = mem.ResourceID
    LEFT JOIN dbo.v_GS_WORKSTATION_STATUS ws ON sys.ResourceID = ws.ResourceID;
"@
    try {
        $sccmResults = Invoke-Sqlcmd -ServerInstance $SqlServer -Database $Database -Query $sqlQuery -QueryTimeout 600 -TrustServerCertificate
        Write-Host "Successfully retrieved $($sccmResults.Count) records from SCCM." -ForegroundColor Cyan
        return $sccmResults
    } catch {
        Write-Error "Failed to execute SQL query. Error: $($_.Exception.Message)"; return $null
    }
}

#=======================================================================================================================
#   Main Script Body
#=======================================================================================================================
Write-Host "Validating input files..." -ForegroundColor Magenta
if (-not (Test-Path -LiteralPath $AdComputersCsvPath -PathType Leaf)) { Write-Error "CRITICAL: AD computers CSV not found: $AdComputersCsvPath. Halting."; exit }
if (-not (Test-Path -LiteralPath $OuExclusionFilePath -PathType Leaf)) { Write-Error "CRITICAL: OU exclusion file not found: $OuExclusionFilePath. Halting."; exit }
Write-Host "Input files validated successfully." -ForegroundColor Magenta

$allFilteredAdComputers = Get-FilteredAdComputers -CsvPath $AdComputersCsvPath -ExclusionFilePath $OuExclusionFilePath -AdExclusionGroup $ExclusionGroupName -HardcodedOus $HardcodedExcludedOus
if (-not $allFilteredAdComputers) { Write-Error "Could not retrieve filtered AD computers. Stopping script."; exit }

# --- Generate Workstation Report ---
Write-Host "`n---------- Generating WORKSTATION Compliance Report ----------" -ForegroundColor Yellow
$workstationAdComputers = $allFilteredAdComputers | Where-Object { $_.OSName -notlike "*Server*" }
$sccmWorkstationData = Get-SccmComplianceData -SqlServer $SccmSqlServer -Database $SccmDbName -CollectionID $WorkstationCollectionID -SugCiId $WorkstationSugCiId
$sccmWorkstationHash = @{}
if ($sccmWorkstationData) { $sccmWorkstationData | ForEach-Object { $sccmWorkstationHash[$_.ComputerName] = $_ } }
$workstationReport = foreach ($adComputer in $workstationAdComputers) {
    $computerName = $adComputer.CanonicalName.Split('/')[-1]
    if (-not [string]::IsNullOrWhiteSpace($computerName)) {
        $domain = ($adComputer.CanonicalName.Split('.'))[0]
        $sccmRecord = $sccmWorkstationHash[$computerName]
        if ($sccmRecord) { [PSCustomObject]@{ ComputerName = $sccmRecord.ComputerName; Domain = $domain; ComplianceStatus = $sccmRecord.ComplianceStatus; RequiredUpdates = $sccmRecord.RequiredUpdates; whenChanged = $adComputer.whenChanged; CanonicalName = $adComputer.CanonicalName; OSName = $adComputer.OSName; LastHardwareScan = $sccmRecord.LastHardwareScan; FreeSpaceC_GB = $sccmRecord.FreeSpaceC_GB; TotalRAM_GB = $sccmRecord.TotalRAM_GB; IsClientActive = $sccmRecord.IsClientActive; IsNameDuplicate = $sccmRecord.IsNameDuplicate }
        } else { [PSCustomObject]@{ ComputerName = $computerName; Domain = $domain; ComplianceStatus = 'Not Found in SCCM'; RequiredUpdates = 'N/A'; whenChanged = $adComputer.whenChanged; CanonicalName = $adComputer.CanonicalName; OSName = $adComputer.OSName; LastHardwareScan = 'N/A'; FreeSpaceC_GB = 'N/A'; TotalRAM_GB = 'N/A'; IsClientActive = 'No'; IsNameDuplicate = 'N/A' } }
    }
}
$workstationReportFile = Join-Path -Path $ReportOutputPath -ChildPath "Workstations_Compliance_Report_$(Get-Date -Format 'yyyy-MM-dd').csv"
$reportDir = Split-Path -Path $workstationReportFile -Parent
if (-not (Test-Path -Path $reportDir)) { New-Item -Path $reportDir -ItemType Directory -Force | Out-Null }
$workstationReport | Export-Csv -Path $workstationReportFile -NoTypeInformation -Encoding UTF8
Write-Host "Workstation report generated successfully: $workstationReportFile" -ForegroundColor Yellow

# --- Generate Server Report ---
Write-Host "`n---------- Generating SERVER Compliance Report ----------" -ForegroundColor Yellow
$serverAdComputers = $allFilteredAdComputers | Where-Object { $_.OSName -like "*Server*" }
$sccmServerData = Get-SccmComplianceData -SqlServer $SccmSqlServer -Database $SccmDbName -CollectionID $ServerCollectionID -SugCiId $ServerSugCiId
$sccmServerHash = @{}
if ($sccmServerData) { $sccmServerData | ForEach-Object { $sccmServerHash[$_.ComputerName] = $_ } }
$serverReport = foreach ($adComputer in $serverAdComputers) {
    $computerName = $adComputer.CanonicalName.Split('/')[-1]
    if (-not [string]::IsNullOrWhiteSpace($computerName)) {
        $domain = ($adComputer.CanonicalName.Split('.'))[0]
        $sccmRecord = $sccmServerHash[$computerName]
        if ($sccmRecord) { [PSCustomObject]@{ ComputerName = $sccmRecord.ComputerName; Domain = $domain; ComplianceStatus = $sccmRecord.ComplianceStatus; RequiredUpdates = $sccmRecord.RequiredUpdates; whenChanged = $adComputer.whenChanged; CanonicalName = $adComputer.CanonicalName; OSName = $adComputer.OSName; LastHardwareScan = $sccmRecord.LastHardwareScan; FreeSpaceC_GB = $sccmRecord.FreeSpaceC_GB; TotalRAM_GB = $sccmRecord.TotalRAM_GB; IsClientActive = $sccmRecord.IsClientActive; IsNameDuplicate = $sccmRecord.IsNameDuplicate }
        } else { [PSCustomObject]@{ ComputerName = $computerName; Domain = $domain; ComplianceStatus = 'Not Found in SCCM'; RequiredUpdates = 'N/A'; whenChanged = $adComputer.whenChanged; CanonicalName = $adComputer.CanonicalName; OSName = $adComputer.OSName; LastHardwareScan = 'N/A'; FreeSpaceC_GB = 'N/A'; TotalRAM_GB = 'N/A'; IsClientActive = 'No'; IsNameDuplicate = 'N/A' } }
    }
}
$serverReportFile = Join-Path -Path $ReportOutputPath -ChildPath "Servers_Compliance_Report_$(Get-Date -Format 'yyyy-MM-dd').csv"
if (-not (Test-Path -Path (Split-Path -Path $serverReportFile -Parent))) { New-Item -Path (Split-Path -Path $serverReportFile -Parent) -ItemType Directory -Force | Out-Null }
$serverReport | Export-Csv -Path $serverReportFile -NoTypeInformation -Encoding UTF8
Write-Host "Server report generated successfully: $serverReportFile" -ForegroundColor Yellow

Write-Host "`nAll reports generated." -ForegroundColor Green
#=======================================================================================================================
#   FINAL: Summary and Email Section
#=======================================================================================================================
Write-Host "`n---------- Generating Summary and Sending Email ----------" -ForegroundColor Magenta

# Create Workstation Summary
$workstationSummary = $workstationReport | Group-Object -Property ComplianceStatus -NoElement | Sort-Object -Property Count -Descending
$totalWorkstations = ($workstationReport | Measure-Object).Count

# Create Server Summary
$serverSummary = $serverReport | Group-Object -Property ComplianceStatus -NoElement | Sort-Object -Property Count -Descending
$totalServers = ($serverReport | Measure-Object).Count

# Create a clean object for the HTML table for workstations
$workstationSummaryForHtml = $workstationSummary | Select-Object @{Name="סטטוס תאימות"; Expression={$_.Name}}, @{Name="כמות מחשבים"; Expression={$_.Count}}
$workstationTable = ($workstationSummaryForHtml | ConvertTo-Html -Fragment) -join "`r`n"

# Create a clean object for the HTML table for servers
$serverSummaryForHtml = $serverSummary | Select-Object @{Name="סטטוס תאימות"; Expression={$_.Name}}, @{Name="כמות מחשבים"; Expression={$_.Count}}
$serverTable = ($serverSummaryForHtml | ConvertTo-Html -Fragment) -join "`r`n"

# --- MODIFIED: Added back the h3 color style ---
# Define CSS for the email style, now with RTL support and color
$style = @"
<style>
    body { font-family: Calibri, sans-serif; font-size: 11pt; direction: rtl; }
    table { border-collapse: collapse; width: 450px; }
    th, td { border: 1px solid #cccccc; text-align: right; padding: 8px; }
    th { background-color: #eeeeee; font-weight: bold; }
    h3 { text-align: right; color: #0046c3; } /* Color restored */
    p, b { text-align: right; }
</style>
"@

# Assemble the final HTML body
$emailBody = @"
<html>
<head>
<meta charset="UTF-8">
$style
</head>
<body>
<p>שלום,</p>
<p>מצורף סיכום סטטוס תאימות עדכוני אבטחה. הדוחות המפורטים מצורפים למייל זה.</p>

<h3>סיכום תאימות - תחנות עבודה</h3>
$workstationTable
<p><b>סך הכל תחנות עבודה שנסרקו: $totalWorkstations</b></p>
<br>

<h3>סיכום תאימות - שרתים</h3>
$serverTable
<p><b>סך הכל שרתים שנסרקו: $totalServers</b></p>

<br>
<p><i>דוח זה נוצר באופן אוטומטי.</i></p>
</body>
</html>
"@

# Define Email Parameters
$MailSubject = "דוח תאימות עדכוני אבטחה (שרתים ותחנות) - $(Get-Date -Format 'dd/MM/yyyy')"
$MailAttachments = @($workstationReportFile, $serverReportFile)

# Send Email
if ($SendEmail) {
    Write-Host "Preparing to send email..."
    
    $mailParams = @{
        From       = "Ccompliance_report@company.com"
        To         = "mudale@company.com"
        Subject    = $MailSubject
        Body       = $emailBody
        SmtpServer = "172.16.0.100"
        Encoding   = "Unicode"
        Attachments = $MailAttachments
        BodyAsHtml = $true
        ErrorAction = "Stop"
    }

    try {
        Send-MailMessage @mailParams
        Write-Host "Summary email sent successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to send email. Error: $($_.Exception.Message)"
    }
}
else {
    Write-Host "Email sending is disabled (`$SendEmail` is set to `$false`)."
}
