# Synology Surveillance Station - Analisi Reverse Engineering delle Patch

## Panoramica

Questo documento descrive l'analisi tecnica approfondita delle patch applicate ai binari di Synology Surveillance Station per bypassare il sistema di licenze.

**Nota**: Questa analisi e' puramente accademica/educativa per comprendere le tecniche di patching binario.

---

## 1. Struttura del Repository

```
Surveillance-Station/
├── activated.sh          # Script principale di installazione patch
├── official/             # Binari originali Synology
│   └── 9.2.x-xxxxx/     # Versioni per architetture multiple
└── patch/                # Binari modificati (craccati)
    └── 9.2.x-xxxxx/     # Patch per versioni specifiche
```

### Architetture supportate:
- `x86_64` - Intel/AMD 64-bit (NAS standard)
- `armv8` - ARM 64-bit (AArch64)
- `armv7` - ARM 32-bit
- `armada38x`, `armada375`, `armada370` - Marvell ARM
- `monaco`, `comcerto2k`, `hi3535` - SoC specifici
- Varianti speciali: `DVA_3219`, `DVA_3221`, `openvino`

---

## 2. File Patchati

| File | Funzione |
|------|----------|
| `lib/libssutils.so` | Libreria principale - verifica licenze |
| `lib/libssffmpegutils.so` | Utilita' ffmpeg - controlli secondari |
| `sbin/sscamerad` | Daemon gestione telecamere |
| `sbin/sscmshostd` | CMS host daemon |
| `sbin/sscored` | Core daemon |
| `sbin/ssdaemonmonitord` | Monitor daemon |
| `sbin/ssexechelperd` | Execution helper |
| `sbin/ssroutined` | Routine daemon |
| `sbin/ssmessaged` | Messaging daemon |
| `webapi/Camera/src/SYNO.SurveillanceStation.Camera.so` | API Camera (alcune versioni) |

---

## 3. Tecniche di Patching Identificate

### 3.1 Function Bypass (Return 0)

**Pattern**: `31 c0 c3` (x86_64)
- `31 c0` = `xor eax, eax` (imposta EAX = 0)
- `c3` = `ret` (ritorna dalla funzione)

**Esempio - libssutils.so @ offset 0x23f10c**:
```
ORIGINAL: 41 55 41 54 ba 0a 00 00 00 55  (push r13; push r12; mov edx, 10; push rbp)
PATCHED:  31 c0 c3 54 ba 0a 00 00 00 55  (xor eax,eax; ret; ...)
```

**Effetto**: La funzione di verifica licenza ritorna immediatamente 0 (successo) invece di eseguire la logica di controllo.

### 3.2 Conditional Jump to Unconditional Jump

**Pattern**: `0f 8c` -> `e9` / `74` -> `eb`

**Esempio - libssffmpegutils.so @ offset 0x3a70a**:
```
ORIGINAL: 74 0b  (jz +11)   - salta se zero
PATCHED:  eb 12  (jmp +18)  - salta sempre
```

**Esempio - sscored @ offset 0x43b4**:
```
ORIGINAL: 0f 8c 57 ff ff ff  (jl -0xa9)   - salta se minore
PATCHED:  e9 58 ff ff ff 90  (jmp; nop)   - salta sempre incondizionatamente
```

### 3.3 NOP Slide (Rimozione Controlli)

**Pattern**: Istruzioni sostituite con `90` (NOP)

**Esempio - libssutils.so @ offset 0x3f0a46**:
```
ORIGINAL: 7f c5      (jg -0x3b)  - salta se maggiore
PATCHED:  90 90      (nop; nop)  - nessuna operazione
```

**Effetto**: Il controllo condizionale viene completamente rimosso.

### 3.4 Call Patching

**Esempio - libssutils.so @ offset 0x23f990**:
```
ORIGINAL: e8 3c 99 e7 ff  (call <funzione_verifica>)
PATCHED:  31 c0 90 90 90  (xor eax,eax; nop; nop; nop)
```

**Effetto**: La chiamata alla funzione di verifica e' sostituita con return 0 + padding NOP.

### 3.5 Server URL Redirection

**Modifica stringhe in libssutils.so**:

| Originale | Modificato |
|-----------|------------|
| `/license_check.php?dsSN=` | `synology.com\0` + null padding |
| `synosurveillance.synology.com` | `192.168.250.250` + null padding |

**Effetto**: Le richieste di verifica licenza vengono reindirizzate a un IP locale/fittizio che non risponde, causando il fallback alla modalita' "offline".

### 3.6 Hardcoded Values

**Esempio - libssutils.so @ offset 0x2434f9**:
```
ORIGINAL: c7 43 18 00 00 00 00  (mov [rbx+0x18], 0)
PATCHED:  c7 43 18 7d 00 00 00  (mov [rbx+0x18], 125)
```

**Effetto**: Imposta un numero di licenze hardcoded (125 = 0x7d) invece di leggere il valore dal server.

### 3.7 Return Code Modification

**Esempio - libssutils.so @ offset 0x23f7b9 e 0x23f881**:
```
ORIGINAL: 41 bd 41 00 00 00  (mov r13d, 0x41)  - codice errore 'A'
PATCHED:  41 bd 7d 00 00 00  (mov r13d, 0x7d)  - codice successo '}'
```

---

## 4. Analisi Dettagliata delle Patch per File

### 4.1 libssutils.so (Libreria Principale)

**Dimensione**: ~5.7 MB (identica tra original e patched)
**Numero di patch**: ~68 byte modificati in totale

| Offset | Originale | Patch | Tipo |
|--------|-----------|-------|------|
| 0x23f10c | `41 55 41` | `31 c0 c3` | Function bypass |
| 0x23f7b9 | `41 00 00 00` | `7d 00 00 00` | Return code |
| 0x23f881 | `43 00 00 00` | `7d 00 00 00` | Return code |
| 0x23f990 | `e8 3c 99 e7 ff` | `31 c0 90 90 90` | Call patching |
| 0x2434f9 | `00 00 00 00` | `7d 00 00 00` | Hardcoded value |
| 0x3f0a09 | `85 c0 74` | `90 90 eb` | NOP + jmp |
| 0x3f0a46 | `7f c5` | `90 90` | NOP slide |
| 0x4d3b54 | `/license_check.php` | `synology.com\0` | URL redirect |
| 0x4d3ba2 | `synosurveillance.synology.com` | `192.168.250.250` | Server redirect |

### 4.2 libssffmpegutils.so

**Patch singola** @ offset 0x3a70a:
```
74 0b -> eb 12  (jz -> jmp)
```

### 4.3 sscmshostd

**Patch** @ offset 0x27d30:
```
41 57 41 -> 31 c0 c3  (function bypass)
```

### 4.4 sscored

**Patch 1** @ offset 0x43b4:
```
0f 8c 57 ff ff ff -> e9 58 ff ff ff 90  (jl -> jmp)
```

**Patch 2** @ offset 0x6610:
```
41 54 55 -> 31 c0 c3  (function bypass)
```

### 4.5 Altri Daemon

Tutti seguono pattern simili con `31 c0 c3` per bypassare funzioni di verifica.

---

## 5. Flusso di Verifica Licenza (Originale)

```
1. Surveillance Station avvia
2. libssutils.so verifica licenza:
   a. Legge serial number NAS
   b. Costruisce URL: synosurveillance.synology.com/license_check.php?dsSN=XXX&token=...
   c. Invia richiesta HTTPS al server Synology
   d. Riceve risposta con numero licenze valide
   e. Verifica firma digitale risposta
   f. Se valida, applica limite telecamere
   g. Se fallisce, usa licenza di prova (2 telecamere)
```

## 6. Flusso Post-Patch

```
1. Surveillance Station avvia
2. libssutils.so (patchata):
   a. Funzione verifica -> return 0 immediatamente
   b. URL reindirizzato a 192.168.250.250 (non raggiungibile)
   c. Numero licenze hardcoded a 125
   d. Controlli condizionali bypassati
3. Risultato: tutte le telecamere abilitate senza limite
```

---

## 7. Protezioni Synology Identificate

1. **Verifica Server-Side**: Controllo licenza via HTTPS a synosurveillance.synology.com
2. **Token Obfuscation**: Token `_sUrvEillAncE_`, `_5Urv_`, `_Eil1@ncE_` nel codice
3. **Binary Stripping**: Rimozione sezioni ELF e simboli per ostacolare reverse engineering
4. **Checksum Verification**: Verifica integrita' (bypassata con patch)
5. **Multiple Verification Points**: Controlli distribuiti in piu' binari

---

## 8. Script di Installazione (activated.sh)

```bash
# Workflow:
1. Verifica root e sistema Synology
2. Determina versione e architettura installata
3. Scarica patch da GitHub (se non locali)
4. Ferma Surveillance Station
5. Backup originali (*_backup)
6. Copia file patchati
7. Imposta permessi (SurveillanceStation:SurveillanceStation, 0755)
8. Riavvia Surveillance Station
```

---

## 9. Conclusioni Tecniche

Le patch utilizzano tecniche classiche di binary patching:

1. **Minimalismo**: Solo i byte necessari sono modificati
2. **Dimensione invariata**: File size identica evita detection banale
3. **Multi-layer bypass**: Patch a libreria + daemon per ridondanza
4. **String patching**: Redirect server per fallback offline
5. **Compatibilita'**: Patch separate per ogni architettura/versione

---

## 10. Note Legali

Questa analisi e' esclusivamente a scopo educativo e di ricerca accademica.
L'utilizzo di queste tecniche per bypassare protezioni software commerciale
puo' violare:
- Termini di servizio Synology
- Leggi sul copyright (DMCA, EUCD)
- Contratti di licenza software

**Disclaimer**: L'autore non si assume responsabilita' per l'uso improprio
di queste informazioni.
