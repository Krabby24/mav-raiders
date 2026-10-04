# Piano d'Attacco — Internet of Drones

**Riccardo Citron • Marco Stocco — Università degli Studi di Padova**  
**Presentazione finale: 25 Marzo 2026**

\---

## Indice

1. [Premessa e obiettivo](#1-premessa-e-obiettivo)
2. [Risultati analisi PCAP](#2-risultati-analisi-pcap)
3. [Architettura dell'attacco](#3-architettura-dellattacco)
4. [Script disponibili](#4-script-disponibili)
5. [FASE 0 — Preparazione](#fase-0--preparazione)
6. [FASE 1 — Lancio ambiente simulazione](#fase-1--lancio-ambiente-simulazione)
7. [FASE 2 — Ricognizione passiva](#fase-2--ricognizione-passiva-recon)
8. [FASE 3 — Strategy B: Attacchi su QGC](#fase-3--strategy-b-attacchi-su-qgc)
9. [FASE 4 — Strategy A: Fuzzing QGC](#fase-4--strategy-a-fuzzing-qgc)
10. [FASE 5 — Pivot: Controllo flotta](#fase-5--pivot-controllo-flotta-3-droni)
11. [FASE 6 — Mission Deception](#fase-6--mission-deception-opzionale)
12. [Ordine demo presentazione](#ordine-demo-presentazione-25-marzo)
13. [Checklist progresso](#checklist-progresso)
14. [Note tecniche](#note-tecniche)

\---

## 1\. Premessa e obiettivo

### Obiettivo del progetto

Dimostrare che avendo il controllo fisico di **un solo drone** della flotta,
è possibile:

1. Attaccare QGroundControl (GCS) manipolando ciò che l'operatore vede
2. Cercare vulnerabilità nel parser MAVLink di QGC (crash/RCE)
3. Prendere controllo degli **altri droni della flotta** impersonando QGC

### Perché è possibile — vulnerabilità fondamentale

Il traffico MAVLink tra PX4 e QGC è **MAVLink v2 completamente non firmato**.

* 102.477 pacchetti analizzati → **0 firmati**
* Nessuna autenticazione, nessuna cifratura
* Chiunque possa inviare UDP sulla porta 18570 può impersonare qualsiasi nodo
* Non serve crackare nessuna chiave

### Due strategie

|Strategia|Nome|Obiettivo|
|-|-|-|
|**A**|Fuzzing|Trovare crash/bug nel parser di QGC|
|**B**|Injection|Controllo diretto di QGC e degli altri droni|

> \*\*Nota\*\*: la Strategy B è il vettore principale. La Strategy A è complementare.
> Se la Strategy A produce un crash → risultato bonus significativo.

\---

## 2\. Risultati analisi PCAP

*Da `mavlink\_analyzer.py` e `mavlink\_inspector.py` sul file cattura\_test\_20260313\_115900.pcap*

### Topologia di rete confermata

```
Drone  →  sysid=1,   compid=1,   IP=172.25.12.121, porta UDP 18570
QGC    →  sysid=255, compid=190, IP=172.25.0.1,    porta UDP 18570
```

### Statistiche traffico

* MAVLink v1: **0 pacchetti**
* MAVLink v2: **102.477 pacchetti**
* MAVLink v2 firmati: **0**
* MAVLink v2 non firmati: **102.477** ← vulnerabili

### Messaggi dominanti (telemetria drone → QGC)

|MsgID|Nome|Count|%|
|-|-|-|-|
|33|GLOBAL\_POSITION\_INT|13.732|13.4%|
|32|LOCAL\_POSITION\_NED|13.732|13.4%|
|30|ATTITUDE|13.732|13.4%|
|31|ATTITUDE\_QUATERNION|13.732|13.4%|
|85|POSITION\_TARGET\_LOCAL\_NED|13.732|13.4%|
|36|SERVO\_OUTPUT\_RAW|13.732|13.4%|
|83|ATTITUDE\_TARGET|13.732|13.4%|
|76|COMMAND\_LONG|21|0.02%|
|253|STATUSTEXT|11|0.01%|

### STATUSTEXT catturati (ciclo di volo completo)

```
\[INFO] Armed by external command
\[INFO] Takeoff detected
\[INFO] Executing Mission
\[INFO] Climb to 15.0 meters above home
\[INFO] Mission finished, loitering
\[INFO] Returning to launch
\[INFO] RTL: start return at 31 m (30 m above destination)
\[INFO] RTL: land at destination
\[INFO] Landing detected
\[INFO] Disarmed by external command
```

### Sequence numbers

* sysid=1  (drone): 102.166 pacchetti, gap=2, reset=1
* sysid=255 (QGC):  311 pacchetti, **gap=0, reset=0** ← completamente prevedibile

### Messaggi UNKNOWN (estensioni PX4)

* UNKNOWN\_436 (137 occorrenze) — microDDS interno
* UNKNOWN\_12901 (275 occorrenze) — estensione PX4 proprietaria
* UNKNOWN\_12904 (275 occorrenze) — estensione PX4 proprietaria
* UNKNOWN\_8 (275 occorrenze) — non standard

> Questi msgid sconosciuti vengono comunque elaborati dal parser di QGC →
> superficie di attacco interessante per il fuzzer.

\---

## 3\. Architettura dell'attacco

```
┌─────────────────────────────────────────────────────────────┐
│                    RETE MAVLink (UDP 18570)                  │
│                                                             │
│  \[DRONE 1]          \[QGC Windows]         \[DRONE 2/3]      │
│  sysid=1            sysid=255             sysid=2,3         │
│  172.25.12.121      172.25.0.1            172.25.12.121     │
│       ▲                  ▲                     ▲            │
│       │                  │                     │            │
│  CONTROLLATO         TARGET                TARGET           │
│  dall'attaccante     Strategy A+B          Strategy B       │
│                                                             │
│  \[ATTACCANTE — script Python su Windows]                    │
│  Impersona sysid=1 → attacca QGC         (inject\_qgc.py)   │
│  Impersona sysid=255 → controlla droni   (inject\_drones.py)│
└─────────────────────────────────────────────────────────────┘
```

\---

## 4\. Script disponibili

|File|Strategia|Scopo|
|-|-|-|
|`recon.py`|—|Ricognizione passiva, mappa tutti i nodi|
|`inject\_qgc.py`|B|Injection verso QGC impersonando il drone|
|`inject\_drones.py`|B|Injection verso droni impersonando QGC|
|`fuzzer.py`|A|Fuzzing del parser MAVLink di QGC|

### Dipendenze

```bash
pip install pymavlink scapy colorama tabulate
```

### CONFIG da aggiornare (se IP WSL2 cambia)

In `inject\_qgc.py` e `inject\_drones.py`, sezione CONFIG in cima al file:

```python
DRONE = {"sysid": 1, "compid": 1, "ip": "172.25.12.121", "port": 18570}
GCS   = {"sysid": 255, "compid": 190, "ip": "172.25.0.1", "port": 18570}
```

Per i 3 droni, aggiornare anche FLEET in `inject\_drones.py`:

```python
FLEET = \[
    {"sysid": 1, "compid": 1, "ip": "172.25.12.121", "port": 18570},
    {"sysid": 2, "compid": 1, "ip": "172.25.12.121", "port": 18571},
    {"sysid": 3, "compid": 1, "ip": "172.25.12.121", "port": 18572},
]
```

> I valori esatti li fornisce `recon.py` quando i droni sono attivi.

\---

## FASE 0 — Preparazione

**Una volta sola — setup iniziale.**

### 0.1 Installa dipendenze Python (Windows)

```bash
pip install pymavlink scapy colorama tabulate
```

### 0.2 Organizza i file

Metti tutti e 4 gli script in una cartella dedicata, es:

```
<PROJECT\_ROOT>\\
├── recon.py
├── inject\_qgc.py
├── inject\_drones.py
└── fuzzer.py
```

Apri questa cartella in VSCode.

### 0.3 Verifica IP WSL2

Ogni riavvio Windows l'IP di WSL2 può cambiare:

```bash
# Da WSL2
ip addr show eth0 | grep 'inet '
```

Se diverso da `172.25.12.121` → aggiorna CONFIG negli script.

**Stato:** ☐ Completato

\---

## FASE 1 — Lancio ambiente simulazione

### 1.1 Lancia PX4 + Gazebo (WSL2)

```bash
cd \~/PX4-Autopilot
make px4\_sitl gz\_x500
```

Attendi il prompt `pxh>` — significa che PX4 è pronto.

### 1.2 Apri QGC (Windows)

Avvia QGroundControl. Aspetta che il drone appaia sulla mappa.
Verifica: drone visibile, stato STANDBY, disarmato.

### 1.3 Verifica connettività

Da WSL2, conferma che il traffico MAVLink stia girando:

```bash
sudo tcpdump -i eth0 -c 10 udp port 18570
```

Devono apparire pacchetti. Se no, c'è un problema di rete.

**Stato:** ☐ Completato

\---

## FASE 2 — Ricognizione passiva (recon.py)

**Sempre prima di qualsiasi attacco.**

```bash
python recon.py --duration 10
```

### Cosa fa

* Ascolta passivamente UDP 18570 per 10 secondi
* Non invia nulla — solo osservazione
* Mappa sysid, compid, IP, porta, versione MAVLink di ogni nodo
* Verifica se i messaggi sono firmati o no
* Stampa la CONFIG da copiare negli altri script

### Cosa verificare nell'output

```
✓ sysid=1   compid=1   IP=172.25.12.121  Firmato=NO
✓ sysid=255 compid=190 IP=172.25.0.1     Firmato=NO
✓ "injection diretta possibile"
```

### Con 3 droni

```bash
python recon.py --duration 15 --port 18570
```

Poi aggiorna FLEET in `inject\_drones.py` con i valori trovati.

**Stato:** ☐ Completato

\---

## FASE 3 — Strategy B: Attacchi su QGC

### Attacco 3.1 — Fake Heartbeat (manipolazione stato UI)

```bash
python inject\_qgc.py --attack A
```

**Cosa fa:**
Invia 30 HEARTBEAT costruiti manualmente impersonando il drone (sysid=1).
I pacchetti sono MAVLink v2 validi con CRC corretto.
Alterna stati: EMERGENCY+ARMED → CRITICAL+AUTO → STANDBY+DISARMED.

**Cosa vedi su QGC:**
L'icona del drone cambia stato continuamente.
Compaiono allarmi, lo stato armed/disarmed cambia,
icone di emergenza appaiono nella UI.

**Perché funziona:**
QGC aggiorna la UI ad ogni HEARTBEAT valido dal sysid del drone.
Non autentica il mittente in nessun modo.

**Stato:** ☐ Completato

\---

### Attacco 3.2 — STATUSTEXT injection (messaggi falsi in QGC)

```bash
python inject\_qgc.py --attack B
```

Oppure con messaggio personalizzato:

```bash
python inject\_qgc.py --attack B --message "Unauthorized access confirmed"
```

**Cosa fa:**
Invia 6 pacchetti STATUSTEXT impersonando il drone.
Messaggi: "CRITICAL: Battery at 1%", "WARNING: GPS signal lost",
"ERROR: Motor 2 failure detected", ecc.

**Cosa vedi su QGC:**
I messaggi appaiono nella console di QGC come se venissero
dal drone. Indistinguibili dai messaggi legittimi.

**Rilevanza per sicurezza:**
Un attaccante può indurre l'operatore a compiere azioni
sbagliate basandosi su informazioni false (social engineering digitale).

**Stato:** ☐ Completato

\---

### Attacco 3.3 — Emergency State Flood

```bash
python inject\_qgc.py --attack C --duration 15
```

**Cosa fa:**
Per 15 secondi a 20 Hz invia HEARTBEAT EMERGENCY +
GLOBAL\_POSITION\_INT con coordinate GPS false casuali.
\~600 pacchetti totali.

**Cosa vedi su QGC:**
La UI va in tilt. La posizione del drone sulla mappa
salta ovunque. Allarmi multipli simultanei.
L'operatore perde il riferimento sulla situazione reale.

**Categoria:** Denial-of-Information attack.

**Stato:** ☐ Completato

\---

### Attacco 3.4 — Telemetry Flood ad alta frequenza

```bash
python inject\_qgc.py --attack D --count 1000
```

**Cosa fa:**
Invia 1000 pacchetti di telemetria (ATTITUDE, GLOBAL\_POSITION\_INT,
HEARTBEAT) alla massima velocità possibile.
Testa la capacità di QGC di gestire picchi di traffico anomali.

**Stato:** ☐ Completato

\---

## FASE 4 — Strategy A: Fuzzing QGC

> \*\*Importante:\*\* Prima di lanciare, apri Task Manager su Windows
> e tieni d'occhio il processo `QGroundControl.exe`.
> Se crasha → annota l'orario esatto → corrisponde all'ultimo
> pacchetto stampato dallo script → quella è la vulnerabilità trovata.

### Fuzzing 4.1 — Smart fuzzing (consigliato come primo)

```bash
python fuzzer.py --mode smart --count 2000
```

**Cosa fa:**
Per ogni msgid target (HEARTBEAT, ATTITUDE, GLOBAL\_POSITION\_INT,
STATUSTEXT, COMMAND\_LONG) invia payload mutati con:

* Valori NaN IEEE 754 nei campi float
* Valori INF e -INF
* INT32\_MAX e INT32\_MIN nei campi interi
* Payload tutto-zero, tutto-0xFF
* Format string (`%s%n%x`) nel campo testo di STATUSTEXT
* Lunghezze boundary (0, 1, 9, 51, 128, 255 bytes)

**CRC:** calcolato correttamente → i pacchetti superano
il controllo CRC e arrivano al parser vero di QGC.

\---

### Fuzzing 4.2 — Targeted STATUSTEXT (target prioritario)

```bash
python fuzzer.py --mode target --msgid 253 --count 3000
```

**Perché STATUSTEXT è prioritario:**
Il campo testo è 50 bytes. Il codice C++ di QGC che lo
legge e lo visualizza nella UI è un punto classico per:

* Buffer overflow
* Format string vulnerability
* Null-byte injection

\---

### Fuzzing 4.3 — Targeted messaggi ad alta frequenza

```bash
python fuzzer.py --mode target --msgid 33 --count 2000
python fuzzer.py --mode target --msgid 30 --count 2000
```

QGC elabora questi messaggi \~14 volte al secondo.
Un bug nel loro parser si manifesta rapidamente sotto fuzzing.

\---

### Fuzzing 4.4 — Dumb fuzzing (copertura ampia)

```bash
python fuzzer.py --mode dumb --count 5000
```

**Cosa fa:**
Payload completamente casuale su msgid random (0-255 + UNKNOWN).
A volte corrompe intenzionalmente il CRC (10% dei casi)
per testare come QGC gestisce pacchetti con checksum errato.

\---

### Fuzzing 4.5 — Length fuzzing

```bash
python fuzzer.py --mode length
```

**Cosa fa:**
Per ogni msgid, testa sistematicamente tutte le lunghezze
da 0 a 255 bytes. Obiettivo: off-by-one, buffer overflow
da length mismatch tra header e payload effettivo.

\---

### Se trovi un crash — cosa fare

1. Annota l'orario esatto del crash
2. Guarda l'ultimo output stampato dallo script → msgid + tipo payload + lunghezza
3. Riproduci il crash con:

```bash
python fuzzer.py --mode target --msgid <msgid\_trovato> --count 100
```

4. Se riproducibile → hai trovato una vulnerabilità documentabile
5. Salva il pacchetto esatto (raw hex dall'output dello script)
6. Descrivi nella presentazione: tipo di crash, pacchetto trigger, impatto potenziale

**A cosa serve il crash nel progetto:**

* Livello 1 — **DoS**: un pacchetto crasha QGC → operatore perde controllo flotta
* Livello 2 — **Dimostrazione**: vulnerabilità reale nel software, non solo teoria
* Livello 3 — **RCE potenziale**: se è buffer overflow → potrebbe eseguire
codice arbitrario sulla macchina dell'operatore (menzionare in presentazione
anche senza implementarlo)

**Stato:** ☐ Completato

\---

## FASE 5 — Pivot: Controllo flotta (3 droni)

> Richiede 3 droni attivi. Prima aggiorna FLEET in `inject\_drones.py`
> con i valori di `recon.py`.

### 5.1 — RTL forzato su tutta la flotta

```bash
python inject\_drones.py --attack C
```

**Cosa fa:**
Invia COMMAND\_LONG con MAV\_CMD\_NAV\_RETURN\_TO\_LAUNCH (cmd=20)
a ogni drone della flotta, impersonando QGC (sysid=255, compid=190).
Ogni comando viene inviato 3 volte (confirmation=0,1,2)
come richiede il protocollo MAVLink per comandi critici.

**Cosa vedi:**
Tutti i droni tornano alla home position simultaneamente
in Gazebo e QGC, esattamente come se l'operatore avesse
premuto RTL — ma il drone compromesso ha fatto tutto da solo.

\---

### 5.2 — Disarm forzato droni 2 e 3

```bash
python inject\_drones.py --attack A --target-sysid 2
python inject\_drones.py --attack A --target-sysid 3
```

**Cosa fa:**
Disarma i droni 2 e 3 impersonando QGC.
Se i droni sono in volo → cadono.
È l'attacco più distruttivo e dimostrativo.

\---

### 5.3 — SET\_MODE forzato

```bash
python inject\_drones.py --attack B --target-sysid 2 --mode HOLD
python inject\_drones.py --attack B --target-sysid 3 --mode LAND
```

**Modalità disponibili:** RTL, HOLD, LAND, TAKEOFF, MISSION, MANUAL

\---

### 5.4 — TAKEOFF forzato

```bash
python inject\_drones.py --attack D --target-sysid 2 --altitude 15
```

Arma e fa decollare il drone 2 a 15 metri.
Prima arma (ARM), poi invia TAKEOFF con altitudine specificata.

\---

## FASE 6 — Mission Deception (opzionale)

```bash
python inject\_drones.py --attack F --target-sysid 2
```

**Cosa fa (sequenza automatica):**

1. MISSION\_CLEAR\_ALL → cancella la missione corrente del drone 2
2. MISSION\_COUNT → annuncia nuova missione con 5 waypoint
3. MISSION\_ITEM × 5 → invia waypoint falsi disposti a cerchio
4. MISSION\_START → avvia la missione

**Cosa vedi:**
Il drone 2 esegue fedelmente la missione falsa in Gazebo —
si muove verso i waypoint che noi abbiamo scelto,
credendo di eseguire la missione originale dell'operatore.

**Perché è spettacolare per la presentazione:**
È visivamente inequivocabile. Il drone va dove diciamo noi,
non dove l'operatore ha programmato.

**Stato:** ☐ Completato

\---

## Ordine demo presentazione 25 Marzo

|Ordine|Script|Comando|Cosa mostra|
|-|-|-|-|
|1|recon.py|`python recon.py --duration 10`|Identificazione nodi, conferma no-firma|
|2|inject\_qgc.py|`--attack B --message "..."`|Messaggi falsi in QGC — impatto immediato|
|3|inject\_qgc.py|`--attack A`|Stato drone falsificato nella UI|
|4|inject\_qgc.py|`--attack C --duration 10`|Flood emergenza, UI inutilizzabile|
|5|fuzzer.py|`--mode smart`|Strategy A, mostra crash se trovato|
|6|inject\_drones.py|`--attack C`|RTL tutta la flotta — pivot completo|
|7|inject\_drones.py|`--attack F --target-sysid 2`|Mission Deception — finale spettacolare|

\---

## Checklist progresso

### Setup

* \[ ] Dipendenze Python installate
* \[ ] Script nella cartella dedicata
* \[ ] IP WSL2 verificato e aggiornato nella CONFIG
* \[ ] PX4 + QGC funzionanti con 1 drone

### Analisi completata

* \[x] PCAP catturato (102.477 pacchetti)
* \[x] Analisi con mavlink\_analyzer.py → JSON prodotto
* \[x] Analisi con mavlink\_inspector.py → report.txt prodotto
* \[x] Vulnerabilità fondamentale confermata: MAVLink v2 unsigned

### Strategy B — Injection

* \[ ] recon.py testato con 1 drone
* \[ ] inject\_qgc.py Attack A testato
* \[ ] inject\_qgc.py Attack B testato
* \[ ] inject\_qgc.py Attack C testato
* \[ ] 3 droni attivi contemporaneamente
* \[ ] inject\_drones.py Attack C testato (RTL flotta)
* \[ ] inject\_drones.py Attack F testato (mission deception)

### Strategy A — Fuzzing

* \[ ] fuzzer.py mode=smart testato
* \[ ] fuzzer.py mode=target msgid=253 testato
* \[ ] fuzzer.py mode=dumb testato
* \[ ] Crash trovato e documentato (se presente)

### Presentazione

* \[ ] Demo rehearsal completa
* \[ ] Slide aggiornate con risultati
* \[ ] Chat transcript AI salvati per consegna

\---

## Note tecniche

### Perché il CRC è importante

MAVLink usa un CRC X.25 con un seed (CRC\_EXTRA) diverso per ogni
tipo di messaggio. Il seed è pubblico e definito nello standard.
I nostri script calcolano sempre il CRC correttamente →
i pacchetti superano la verifica CRC e arrivano al parser vero.

### Perché il confirmation field è importante

Per i comandi critici (ARM, RTL, TAKEOFF) MAVLink richiede
che il comando sia inviato più volte con confirmation=0,1,2.
I nostri script lo gestiscono automaticamente.

### IP WSL2 — come ottenerlo sempre

```bash
# Da WSL2
ip addr show eth0 | grep 'inet '

# Da Windows (PowerShell)
wsl hostname -I
```

### Porte PX4 SITL multi-istanza

|Istanza|Drone sysid|Porta UDP|
|-|-|-|
|0|1|18570|
|1|2|18571|
|2|3|18572|

### Come monitorare QGC per crash (fuzzing)

Su Windows, apri Task Manager → Dettagli → cerca `QGroundControl.exe`.
Oppure usa Process Monitor (Sysinternals) per log dettagliato.

### Consegna AI transcript

Il prof richiede di salvare i transcript delle chat AI.
Salva questa conversazione da claude.ai prima della presentazione.

