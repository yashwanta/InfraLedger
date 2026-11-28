package app

import "strings"

// Bundled knowledge base articles shipped with new installations. Keep these
// generic: fictional names, documentation-range addresses and placeholders
// only. Never put a customer's hosts, users, fingerprints or tokens here.

// proxmoxGuideTitle is the title of the bundled Proxmox connection guide.
const proxmoxGuideTitle = "How to connect Proxmox VE so all VMs and containers appear in inventory"

// proxmoxGuide returns the bundled step-by-step Proxmox connection guide.
// "~~~" marks code blocks and is converted to Markdown fences.
func proxmoxGuide() string {
	return strings.ReplaceAll(`## Summary

InfraLedger lists Proxmox VMs and containers only after it is connected to the Proxmox API with a read-only token. Network discovery alone finds Proxmox hosts (it sees port 8006 open) but cannot see the guests running inside them.

This guide uses example values: a cluster named acme-pve with nodes pve01, pve02 and pve03, reached at https://10.10.1.20:8006. Replace them with your own.

Result: guests appear under Infrastructure → Virtual machines & containers after they are approved in Auto Discovery.

## Before you start

You need root (or equivalent) access to the Proxmox web interface and the IT Admin role in InfraLedger.
One connection covers every node in a Proxmox cluster. A standalone host outside the cluster needs its own user, token and connection; repeat Parts 1–5 on that host.

## Part 1 — Create a read-only Proxmox user

1. Sign in to the Proxmox web interface, for example https://10.10.1.20:8006.
2. Go to Datacenter → Permissions → Users → Add.
3. User name: infraledger. Realm: Proxmox VE authentication server (pve).
4. Leave Password empty. The account is used only through its API token and cannot sign in to the web interface.
5. Comment: InfraLedger read-only inventory (API token only). Click Add.

Use a dedicated account. Do not reuse an administrator account or a token that belongs to another tool.

## Part 2 — Create the API token

1. Go to Datacenter → Permissions → API Tokens → Add.
2. User: infraledger@pve. Token ID: inventory.
3. Untick Privilege Separation, so the token uses the user's permission from Part 3.
4. Choose an expiry that matches your policy. Comment: InfraLedger Proxmox inventory sync (read-only).
5. Click Add. Copy the Secret now; Proxmox shows it only once. Then click Done.

The full token ID is:
~~~
infraledger@pve!inventory
~~~

Never paste the secret into tickets, chat or articles. If it is lost, select the token, use Regenerate Secret, then update the InfraLedger connection.

## Part 3 — Give the user read-only access

1. Go to Datacenter → Permissions → Add → User Permission.
2. Path: /   User: infraledger@pve   Role: PVEAuditor   Propagate: ticked.
3. Click Add.

PVEAuditor can view everything and change nothing. In Proxmox VE 9 it includes VM.GuestAgent.Audit, which lets InfraLedger read guest-agent IP and OS details. On Proxmox VE 8, also grant VM.Monitor through a custom role if you want those details.

## Part 4 — Get the certificate fingerprint

Proxmox normally uses a self-signed certificate. InfraLedger will not send the token to a server it cannot verify, so give it the certificate fingerprint (or the cluster CA). Without it the connection shows "Error: Cannot connect to Proxmox… HTTPS certificate trust or fingerprint".

1. In Proxmox, select the node whose address you will connect to, then System → Certificates.
2. Use the SHA-256 fingerprint of pve-ssl.pem (the node certificate), not pve-root-ca.pem. It is 64 hexadecimal characters, usually shown in pairs separated by colons.

Check it independently from another computer on the network before trusting it:
~~~
openssl s_client -connect 10.10.1.20:8006 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
~~~

The two values must match exactly. When Proxmox renews the node certificate, update the fingerprint in the connection. Alternative: paste the cluster CA (pve-root-ca.pem) into "Trusted CA certificate"; it lasts much longer and covers every node in the cluster.

## Part 5 — Add the connection in InfraLedger

1. Go to Setup → Integrations → Proxmox VE — automatic VM & container inventory → Connect Proxmox.
2. Organization: the organization that owns the cluster.
3. URL: https://10.10.1.20:8006 (scheme, address and port only; no path).
4. Token ID: infraledger@pve!inventory
5. Token secret: the secret copied in Part 2.
6. Certificate fingerprint: the value from Part 4.
7. Click Save and start automatic sync.

Saving starts the first sync, which then repeats every 5 minutes by default. After saving, the connection card shows Edit connection, Sync now and Pause sync; there is no Sync now button before a connection exists.

Expected result: status Connected, with a summary of nodes and guests.

## Part 6 — Approve the hosts and guests

Imported hosts and guests start as Pending and do not appear in inventory until approved.

1. Go to Auto Discovery → Awaiting inventory approval.
2. Approve the Proxmox hosts first. Guests cannot be approved before their host.
3. Approve each guest (Review device → Approve and add to inventory).
4. Open Infrastructure → Virtual machines & containers. Each guest is listed with its host, vCPU, memory, disk and state.

## Part 7 (optional) — Live IP addresses and OS details

InfraLedger reads IP addresses, hostname and OS from the QEMU guest agent of running VMs. The guest's inventory record shows the agent status.

"Not enabled": in Proxmox open the VM → Options → QEMU Guest Agent → Enabled, install the agent inside the VM (below), then shut the VM down and start it again. A reboot from inside the guest is not enough.
"Not responding": the option is enabled but the agent is not running inside the VM. Install and start it:
~~~
sudo apt install qemu-guest-agent && sudo systemctl enable --now qemu-guest-agent
~~~
Windows guests: install the QEMU guest agent from the VirtIO drivers ISO.

Containers (LXC) do not use the guest agent; their address comes from the container configuration.

## Troubleshooting

Status Error, "Cannot connect to Proxmox": the fingerprint is missing or wrong, or the URL is unreachable from the InfraLedger server. Edit the connection and enter the fingerprint. Leave the secret field empty to keep the saved secret.
"Re-enter the token secret": the URL or token ID was changed. A new endpoint or token needs its secret entered again.
Fewer guests than expected: the token sees only what its permission allows. Confirm PVEAuditor on / with Propagate ticked, and Privilege Separation off on the token.
Warning "Only resources visible to this token are returned": always shown. Safe to ignore when the permission above is in place.
Guests imported but not in Virtual machines & containers: they are still Pending. Approve the host, then the guests, in Auto Discovery.
A guest removed in Proxmox is not deleted from InfraLedger. It is marked "Not reported in latest Proxmox response".

## What InfraLedger does and does not do

It sends only read-only GET requests to the Proxmox API. It never starts, stops, changes or logs into guests. The token secret is stored encrypted with the vault key, is never shown again by InfraLedger, and is excluded from documentation exports.
`, "~~~", "```")
}
