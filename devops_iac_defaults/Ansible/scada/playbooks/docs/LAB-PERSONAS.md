# Lab persona ↔ playbook matrix (complete coverage, no licenses)

Target: **192.168.2.137**, SSH `pnet` / `pnet`.

```bash
docker exec peregrine11252025 bash /peregrine/data/scada-plc-playbooks/scripts/run-lab-playbook-tests.sh
# Expected: pass=37 fail=0 skip=0
```

## Personas (11 in default suite)

| Persona | Ports | Playbooks exercised |
|---------|-------|---------------------|
| schneider-m221 | :502 | Modbus FC1/FC3, write verify, negative closed port |
| modbuspal | :502 | Static map, automation ramp, write verify |
| rockwell-modbus | :502 | CompactLogix gateway Modbus read |
| rockwell | :44818 | CIP identity, cpppo tag read/write |
| siemens | :102, :8080 | Snap7 DB, REST DataBlocks, S7 write verify |
| beckhoff-ads | :48898 | pyads ADS symbol read/write |
| beckhoff | :48898, :8080 | REST catalog/read/write, ADS negative test |
| opcua | :50000 | Signed multi-node read |
| mitsubishi | :5007 | MC Type3E read/write |
| omron | :9600/udp | FINS DM read/write |
| openplc-v4 | :8443 | JWT 401, login, runtime diagnostics |

Start/stop: `ssh pnet@192.168.2.137 'cd ~/plc-emulator-lab && ./plc-emulator start <persona>'`

## Protocol matrix

| Protocol | Read | Write verify | Lab persona |
|----------|------|--------------|-------------|
| Modbus TCP | ✓ | ✓ | schneider-m221, modbuspal |
| Rockwell CIP | ✓ | ✓ | rockwell (`ab_cip_engine=cpppo`) |
| Rockwell Modbus | ✓ | — | rockwell-modbus |
| Siemens S7 | ✓ | ✓ | siemens |
| Siemens REST | ✓ | — | siemens `/api/DataBlocks` |
| Beckhoff ADS | ✓ | ✓ | **beckhoff-ads** |
| Beckhoff REST | ✓ | ✓ | beckhoff |
| OPC UA signed | ✓ | ✓ | opcua |
| Mitsubishi MC | ✓ | ✓ | mitsubishi |
| Omron FINS | ✓ | ✓ | omron |
| OpenPLC v4 HTTPS | ✓ | — | openplc-v4 |

## Inventory (`inventory-lab-pnetnode.yml`)

- `ab_cip_engine: cpppo` — Logix tag I/O on cpppo emulator
- Write flags enabled for Modbus, AB, Beckhoff, Mitsubishi, Omron, S7
- `beckhoff_symbols: test1,test2,GVL.test1`

## Hardware-only (documented, not in automated pass criteria)

| Item | Lab workaround |
|------|----------------|
| OpenPLC v4 running IEC logic | API tested; STATUS:EMPTY without Editor `program.zip` |
| Rockwell pycomm3 tag catalog | Use `ab_cip_engine=cpppo` or real ControlLogix |
| SoftBeckhoff native ADS | `negative-softbeckhoff-ads.yml` + use **beckhoff-ads** |

## Lab node maintenance

```bash
# On 192.168.2.137 as pnet
cd ~/plc-emulator-lab && ./build-images.sh    # logix-l73, modbuspal, mitsubishi-mc, omron-fins, beckhoff-ads-lab
./test-all-personas.sh                         # port smoke for all personas
```
