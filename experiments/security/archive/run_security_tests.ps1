param(
    [string]$Test = "all",
    [string]$Protocol = "zkarche",
    [string]$HostName = "127.0.0.1",
    [Nullable[int]]$Port = $null,
    [string]$Project = "",
    [string]$LogDir = "results/security/logs",
    [int]$FuzzSeconds = 60,
    [int]$Samples = 10000
)

if ($Project -eq "") {
    $Project = Resolve-Path (Join-Path $PSScriptRoot "..")
} else {
    $Project = Resolve-Path $Project
}

if ($null -eq $Port) {
    switch ($Protocol) {
        "zkarche" { $Port = 4000 }
        "edhoc" { $Port = 5688 }
        "mtls" { $Port = 7443 }
        default { Write-Error "Unsupported protocol for DoS: $Protocol"; exit 2 }
    }
}

Set-Location $Project
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path "results/security" | Out-Null

function Run-TestOne {
    param([string]$Name)
    Write-Host ""
    Write-Host "============================================================"
    Write-Host "Running security test: $Name"
    Write-Host "============================================================"

    switch ($Name) {
        "transcript" {
            python security/transcript_binding_test.py --project $Project --log-dir $LogDir
            return $LASTEXITCODE
        }
        "mutation" {
            python security/message_mutation_test.py --project $Project --log-dir $LogDir
            return $LASTEXITCODE
        }
        "invalid-curve" {
            python security/invalid_curve_small_subgroup_test.py --project $Project --log-dir $LogDir
            return $LASTEXITCODE
        }
        "dos" {
            $log = Join-Path $Project "$LogDir/04_dos_resilience_$Protocol.log"
            python security/dos_resilience_test.py --host $HostName --port $Port --protocol $Protocol --output "results/security/${Protocol}_dos_resilience.csv" 2>&1 | Tee-Object -FilePath $log
            Write-Host "Saved log: $log"
            return $LASTEXITCODE
        }
        "session" {
            python security/session_uniqueness_nonce_reuse_test.py --project $Project --log-dir $LogDir
            return $LASTEXITCODE
        }
        "fuzz" {
            python security/packet_fuzzing_test.py --project $Project --log-dir $LogDir --seconds $FuzzSeconds
            return $LASTEXITCODE
        }
        "replay" {
            python security/replay_cache_test.py --project $Project --log-dir $LogDir
            return $LASTEXITCODE
        }
        "side-channel" {
            python security/side_channel_rng_analysis_test.py --project $Project --log-dir $LogDir --samples $Samples
            return $LASTEXITCODE
        }
        default {
            Write-Error "Unknown test: $Name"
            return 2
        }
    }
}

$failed = 0
if ($Test -eq "all") {
    foreach ($t in @("transcript", "mutation", "invalid-curve", "session", "replay", "side-channel")) {
        $rc = Run-TestOne $t
        if ($rc -ne 0) { $failed = 1 }
    }
    Write-Host ""
    Write-Host "NOTE: DoS and fuzzing are not included in 'all' by default because DoS requires a running server and fuzzing can be long-running."
    Write-Host "Run them explicitly with -Test dos or -Test fuzz."
} else {
    $rc = Run-TestOne $Test
    if ($rc -ne 0) { $failed = 1 }
}

exit $failed
