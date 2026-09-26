# AfricaWatch Security Analysis Lab

## File / malware analysis
The submission endpoint stores files in a tenant-specific quarantine area, computes SHA-256, applies archive-bomb limits, and never executes the submitted artifact. Optional engines are ClamAV, YARA and Semgrep. A finding is evidence for triage, not a verdict of maliciousness.

## Network / exploit validation
Active exploitation is not executed against arbitrary Internet targets. For authorized training, use a separate isolated lab network with deliberately vulnerable targets and pre-approved scenario manifests. This keeps dangerous actions away from production data and the collection plane.
