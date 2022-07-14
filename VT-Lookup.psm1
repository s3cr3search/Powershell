Function Get-IP-Info {
$IP_Address = Read-Host -Prompt 'Input IP Address'

$webIPData = ConvertFrom-Json (Invoke-WebRequest -Uri "https://ipinfo.io/$IP_Address/json?token={Add IP Info API Key}")
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("x-apikey", "{Add VT API Key}")
$response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IP_Address" -Method GET -Headers $headers

$data = $response.data.attributes.last_analysis_results

$datatest = ,$data.Sophos+,$data.'Phishing Database'+,$data.Trustwave+,$data.AlienVault+,$data.Kaspersky+,$data.BitDefender+,$data.MalBeacon+,$data.Malwared+,$data.ESET

$webIPData
$datatest | Format-Table

}

Function Get-URL-Info {
$URL = Read-Host -Prompt 'Input Url'
$EncodedText =[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($URL))
# strip out '='
$Stripped = $EncodedText.Replace('=','')

$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("x-apikey", "{Add VT API Key}")
$response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls/$Stripped" -Method GET -Headers $headers

$data_stats = $response.data.attributes.last_analysis_stats | Format-Table
$data_cat = $response.data.attributes.categories | Format-Table
$data_url = $response.data.attributes.url
$data_votes = $response.data.attributes.total_votes

Write-Output 'URL'
$data_url
Write-Output 'Categories'
$data_cat
Write-Output 'Stats'
$data_stats
Write-Output 'Votes'
$data_votes
}
