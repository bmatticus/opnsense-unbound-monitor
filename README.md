# OPNSense Unbound Monitor

A lightweight Python script (intended to run inside a Docker container) that monitors DNS resolution against the Unbound resolver behind OPNsense.  
If resolution failures are detected, the script will attempt to restart the Unbound service automatically via the OPNsense API.

This was built to address recurring issues where Unbound would silently fail until manually restarted.

---

## Environment Variables

### OPNsense API Configuration
- **OPNSENSE_KEY**  
  API key for a user in OPNsense with permissions to start, stop, and restart the Unbound service.
- **OPNSENSE_SECRET**  
  API key secret corresponding to the above user.
- **OPNSENSE_HOST**  
  Hostname or IP address of your OPNsense instance.
- **OPNSENSE_HOST_SCHEMA**  
  Protocol to use for API calls. Typically `https`.  
  Default: `https`
- **OPNSENSE_HOST_PORT**  
  Port for API calls. Typically `443`.  
  Default: `443`
- **VERIFY_SSL**  
  Whether to verify SSL certificates.  
  Set to `FALSE` if using a self-signed certificate.  
  Default: `TRUE`

### DNS Resolution Configuration
- **HOST_LIST**  
  Comma-separated list of hostnames to test against Unbound.  
  Default: `google.com,reddit.com`
- **OPNSENSE_DNS_IP**  
  IP address where Unbound is listening (often your OPNsense LAN IP).  
  Default: same as `OPNSENSE_HOST`
- **OPNSENSE_DNS_PORT**  
  Port where Unbound is listening.  
  Default: `53`
- **DNS_TIMEOUT**  
  Timeout per DNS query attempt (in seconds).  
  Default: `2.0`
- **DNS_LIFETIME**  
  Maximum lifetime for a DNS query before failing (in seconds).  
  Default: `5.0`
- **DNS_TCP**  
  Whether to use TCP instead of UDP for DNS queries.  
  Default: `FALSE`


### Healthchecks Integration 
- **HEALTHCHECKS_SLUG**  
  SLUG for healthcheck, if this is set the integration is enabled and updates will be sent to this  
  SLUG.

### Script Behavior
- **MAX_ATTEMPTS**  
  Number of retry cycles to attempt resolution before giving up.  
  Default: `1`
- **LOG_LEVEL**  
  Logging verbosity (`ERROR`, `WARNING`, `INFO`, `DEBUG`, etc.).  
  Default: `WARN`
- **INTERVAL**
  Run Interval in seconds  
  Default: `60`

---

## Example Usage

```bash
docker run --rm \
  -e OPNSENSE_KEY=myapikey \
  -e OPNSENSE_SECRET=myapisecret \
  -e OPNSENSE_HOST=192.168.1.1 \
  -e VERIFY_SSL=FALSE \
  -e HOST_LIST="google.com,cloudflare.com" \
  ghcr.io/youruser/opnsense-unbound-monitor:latest

