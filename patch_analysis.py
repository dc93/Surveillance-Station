#!/usr/bin/env python3
"""
Synology Surveillance Station - Analisi Patch a Scopo di Studio
================================================================

Questo script documenta le tecniche di binary patching usate per bypassare
il sistema di licenze di Synology Surveillance Station.

DISCLAIMER: Solo a scopo educativo/accademico. L'uso di queste informazioni
per bypassare protezioni software commerciale puo' violare leggi sul copyright.

Autore: Analisi tecnica
Versione analizzata: 9.2.4-9795 (x86_64)
"""

from dataclasses import dataclass
from typing import List, Optional
from enum import Enum
import struct


class PatchType(Enum):
    """Tipi di patch identificati"""
    FUNCTION_BYPASS = "function_bypass"      # Sostituisce funzione con return 0
    CALL_NOP = "call_nop"                    # Sostituisce call con NOP + return 0
    CONDITIONAL_TO_JUMP = "cond_to_jmp"      # Salto condizionale -> incondizionale
    NOP_SLIDE = "nop_slide"                  # Rimuove istruzioni con NOP
    STRING_REDIRECT = "string_redirect"      # Modifica stringhe (URL/server)
    HARDCODED_VALUE = "hardcoded_value"      # Imposta valori fissi
    RETURN_CODE_MOD = "return_code_mod"      # Modifica codici di ritorno


@dataclass
class Patch:
    """Rappresenta una singola patch binaria"""
    offset: int                 # Offset nel file (decimale)
    original: bytes            # Byte originali
    patched: bytes             # Byte modificati
    patch_type: PatchType      # Tipo di patch
    description: str           # Descrizione leggibile
    asm_original: str = ""     # Assembly originale (opzionale)
    asm_patched: str = ""      # Assembly patchato (opzionale)

    @property
    def offset_hex(self) -> str:
        return f"0x{self.offset:x}"

    def __str__(self) -> str:
        return (
            f"Patch @ {self.offset_hex} ({self.offset}):\n"
            f"  Tipo: {self.patch_type.value}\n"
            f"  Descrizione: {self.description}\n"
            f"  Originale: {self.original.hex(' ')}\n"
            f"  Patchato:  {self.patched.hex(' ')}\n"
            f"  ASM orig:  {self.asm_original}\n"
            f"  ASM patch: {self.asm_patched}"
        )


@dataclass
class BinaryFile:
    """Rappresenta un file binario con le sue patch"""
    name: str
    path: str
    size: int
    patches: List[Patch]

    @property
    def total_bytes_modified(self) -> int:
        return sum(len(p.original) for p in self.patches)

    def __str__(self) -> str:
        return (
            f"File: {self.name}\n"
            f"Path: {self.path}\n"
            f"Size: {self.size:,} bytes\n"
            f"Patches: {len(self.patches)}\n"
            f"Byte modificati: {self.total_bytes_modified}"
        )


# =============================================================================
# PATCH PER libssutils.so (Libreria principale licensing)
# =============================================================================

LIBSSUTILS_PATCHES = [
    # --- PATCH 1: Function Bypass principale ---
    # Questa e' la patch piu' importante: bypassa la funzione di verifica licenza
    Patch(
        offset=2355468,  # 0x23f10c
        original=bytes([0x41, 0x55, 0x41, 0x54]),
        patched=bytes([0x31, 0xc0, 0xc3, 0x54]),
        patch_type=PatchType.FUNCTION_BYPASS,
        description="Bypass funzione verifica licenza principale",
        asm_original="push r13; push r12  (prologo funzione)",
        asm_patched="xor eax, eax; ret   (return 0 immediato)"
    ),

    # --- PATCH 2-3: Modifica codici di ritorno ---
    # Cambia i codici di errore in codici di successo
    Patch(
        offset=2357177,  # 0x23f7b9
        original=bytes([0x41, 0x00, 0x00, 0x00]),
        patched=bytes([0x7d, 0x00, 0x00, 0x00]),
        patch_type=PatchType.RETURN_CODE_MOD,
        description="Cambia codice errore 0x41 ('A') in 0x7d (125)",
        asm_original="mov r13d, 0x41  (codice errore)",
        asm_patched="mov r13d, 0x7d  (codice successo)"
    ),

    Patch(
        offset=2357377,  # 0x23f881
        original=bytes([0x43, 0x00, 0x00, 0x00]),
        patched=bytes([0x7d, 0x00, 0x00, 0x00]),
        patch_type=PatchType.RETURN_CODE_MOD,
        description="Cambia codice errore 0x43 ('C') in 0x7d (125)",
        asm_original="mov r13d, 0x43  (codice errore)",
        asm_patched="mov r13d, 0x7d  (codice successo)"
    ),

    # --- PATCH 4: Call Patching ---
    # Sostituisce una chiamata a funzione di verifica con return 0
    Patch(
        offset=2357648,  # 0x23f990
        original=bytes([0xe8, 0x3c, 0x99, 0xe7, 0xff]),
        patched=bytes([0x31, 0xc0, 0x90, 0x90, 0x90]),
        patch_type=PatchType.CALL_NOP,
        description="Sostituisce call verifica con return 0 + NOP",
        asm_original="call <funzione_verifica_licenza>",
        asm_patched="xor eax, eax; nop; nop; nop"
    ),

    # --- PATCH 5: Hardcoded License Count ---
    # Imposta un numero fisso di licenze invece di leggerlo dal server
    Patch(
        offset=2372857,  # 0x2434f9
        original=bytes([0x00, 0x00, 0x00, 0x00]),
        patched=bytes([0x7d, 0x00, 0x00, 0x00]),
        patch_type=PatchType.HARDCODED_VALUE,
        description="Imposta 125 licenze telecamera hardcoded",
        asm_original="mov dword [rbx+0x18], 0",
        asm_patched="mov dword [rbx+0x18], 125"
    ),

    # --- PATCH 6: Conditional Jump Bypass ---
    # Trasforma test condizionale in salto incondizionale
    Patch(
        offset=4131337,  # 0x3f0a09
        original=bytes([0x85, 0xc0, 0x74]),
        patched=bytes([0x90, 0x90, 0xeb]),
        patch_type=PatchType.CONDITIONAL_TO_JUMP,
        description="Bypass controllo: test+jz diventa nop+jmp",
        asm_original="test eax, eax; jz +0x24",
        asm_patched="nop; nop; jmp +0x24"
    ),

    # --- PATCH 7: NOP Slide ---
    # Rimuove un salto condizionale
    Patch(
        offset=4131398,  # 0x3f0a46
        original=bytes([0x7f, 0xc5]),
        patched=bytes([0x90, 0x90]),
        patch_type=PatchType.NOP_SLIDE,
        description="Rimuove jg (jump if greater) con NOP",
        asm_original="jg -0x3b  (salta se maggiore)",
        asm_patched="nop; nop  (nessuna operazione)"
    ),

    # --- PATCH 8-9: String Redirect (URL e Server) ---
    # Reindirizza le richieste di verifica licenza
    Patch(
        offset=5061460,  # 0x4d3b54
        original=b"/license_check.php?dsSN=",
        patched=b"synology.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        patch_type=PatchType.STRING_REDIRECT,
        description="Elimina URL endpoint verifica licenza",
        asm_original="stringa: /license_check.php?dsSN=",
        asm_patched="stringa: synology.com + null padding"
    ),

    Patch(
        offset=5061538,  # 0x4d3ba2
        original=b"synosurveillance.synology.com",
        patched=b"192.168.250.250\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        patch_type=PatchType.STRING_REDIRECT,
        description="Reindirizza server licenze a IP locale fittizio",
        asm_original="stringa: synosurveillance.synology.com",
        asm_patched="stringa: 192.168.250.250 (non raggiungibile)"
    ),
]


# =============================================================================
# PATCH PER libssffmpegutils.so
# =============================================================================

LIBSSFFMPEGUTILS_PATCHES = [
    Patch(
        offset=239370,  # 0x3a70a
        original=bytes([0x74, 0x0b]),
        patched=bytes([0xeb, 0x12]),
        patch_type=PatchType.CONDITIONAL_TO_JUMP,
        description="Bypass controllo ffmpeg: jz diventa jmp",
        asm_original="jz +11  (salta se zero)",
        asm_patched="jmp +18 (salta sempre)"
    ),
]


# =============================================================================
# PATCH PER sbin/sscored
# =============================================================================

SSCORED_PATCHES = [
    Patch(
        offset=17332,  # 0x43b4
        original=bytes([0x0f, 0x8c, 0x57, 0xff, 0xff, 0xff]),
        patched=bytes([0xe9, 0x58, 0xff, 0xff, 0xff, 0x90]),
        patch_type=PatchType.CONDITIONAL_TO_JUMP,
        description="jl (jump if less) diventa jmp incondizionale",
        asm_original="jl -0xa9  (salta se minore)",
        asm_patched="jmp -0xa8; nop"
    ),

    Patch(
        offset=26128,  # 0x6610
        original=bytes([0x41, 0x54, 0x55]),
        patched=bytes([0x31, 0xc0, 0xc3]),
        patch_type=PatchType.FUNCTION_BYPASS,
        description="Bypass funzione verifica in sscored",
        asm_original="push r12; push rbp  (prologo)",
        asm_patched="xor eax, eax; ret   (return 0)"
    ),
]


# =============================================================================
# PATCH PER sbin/sscmshostd
# =============================================================================

SSCMSHOSTD_PATCHES = [
    Patch(
        offset=163120,  # 0x27d30
        original=bytes([0x41, 0x57, 0x41]),
        patched=bytes([0x31, 0xc0, 0xc3]),
        patch_type=PatchType.FUNCTION_BYPASS,
        description="Bypass funzione verifica CMS host",
        asm_original="push r15; push ...  (prologo)",
        asm_patched="xor eax, eax; ret   (return 0)"
    ),
]


# =============================================================================
# DEFINIZIONE FILE BINARI
# =============================================================================

BINARY_FILES = [
    BinaryFile(
        name="libssutils.so",
        path="lib/libssutils.so",
        size=5741861,
        patches=LIBSSUTILS_PATCHES
    ),
    BinaryFile(
        name="libssffmpegutils.so",
        path="lib/libssffmpegutils.so",
        size=484048,
        patches=LIBSSFFMPEGUTILS_PATCHES
    ),
    BinaryFile(
        name="sscored",
        path="sbin/sscored",
        size=46033,
        patches=SSCORED_PATCHES
    ),
    BinaryFile(
        name="sscmshostd",
        path="sbin/sscmshostd",
        size=418051,
        patches=SSCMSHOSTD_PATCHES
    ),
]


# =============================================================================
# FUNZIONI DI UTILITA'
# =============================================================================

def apply_patches(data: bytearray, patches: List[Patch]) -> bytearray:
    """
    Applica una lista di patch a un bytearray.

    Args:
        data: Dati binari originali
        patches: Lista di patch da applicare

    Returns:
        Dati binari con patch applicate
    """
    result = bytearray(data)
    for patch in patches:
        # Verifica che i byte originali corrispondano
        actual = bytes(result[patch.offset:patch.offset + len(patch.original)])
        if actual != patch.original:
            print(f"WARNING: Offset {patch.offset_hex} non corrisponde!")
            print(f"  Atteso:  {patch.original.hex(' ')}")
            print(f"  Trovato: {actual.hex(' ')}")
            continue

        # Applica la patch
        result[patch.offset:patch.offset + len(patch.patched)] = patch.patched
        print(f"OK: Patch applicata @ {patch.offset_hex}")

    return result


def verify_patches(original: bytes, patched: bytes, patches: List[Patch]) -> bool:
    """
    Verifica che le patch siano state applicate correttamente.

    Args:
        original: Dati binari originali
        patched: Dati binari patchati
        patches: Lista di patch attese

    Returns:
        True se tutte le patch sono corrette
    """
    all_ok = True
    for patch in patches:
        orig_bytes = original[patch.offset:patch.offset + len(patch.original)]
        patch_bytes = patched[patch.offset:patch.offset + len(patch.patched)]

        orig_ok = orig_bytes == patch.original
        patch_ok = patch_bytes == patch.patched

        if not orig_ok:
            print(f"ERRORE: Originale non corrisponde @ {patch.offset_hex}")
            all_ok = False
        if not patch_ok:
            print(f"ERRORE: Patch non corrisponde @ {patch.offset_hex}")
            all_ok = False
        if orig_ok and patch_ok:
            print(f"OK: {patch.offset_hex} - {patch.description[:50]}")

    return all_ok


def disassemble_x86_64(data: bytes, offset: int = 0) -> str:
    """
    Disassembla semplice per istruzioni x86_64 comuni nelle patch.
    (Implementazione minimale per scopo didattico)
    """
    instructions = {
        0x31: "xor",
        0x90: "nop",
        0xc3: "ret",
        0xe8: "call",
        0xe9: "jmp",
        0xeb: "jmp short",
        0x74: "jz",
        0x75: "jnz",
        0x7f: "jg",
        0x0f: "two-byte opcode",
        0x41: "REX.B prefix",
        0x85: "test",
    }

    result = []
    i = 0
    while i < len(data):
        byte = data[i]
        if byte in instructions:
            result.append(f"{offset+i:04x}: {data[i:i+1].hex()} - {instructions[byte]}")
        else:
            result.append(f"{offset+i:04x}: {data[i:i+1].hex()}")
        i += 1

    return "\n".join(result)


def print_patch_summary():
    """Stampa un riepilogo di tutte le patch"""
    print("=" * 70)
    print("RIEPILOGO PATCH SYNOLOGY SURVEILLANCE STATION")
    print("=" * 70)

    total_patches = 0
    total_bytes = 0

    for bf in BINARY_FILES:
        print(f"\n{bf}")
        print("-" * 40)
        for patch in bf.patches:
            print(f"  [{patch.patch_type.value}] @ {patch.offset_hex}")
            print(f"    {patch.description}")
        total_patches += len(bf.patches)
        total_bytes += bf.total_bytes_modified

    print("\n" + "=" * 70)
    print(f"TOTALE: {total_patches} patch, {total_bytes} byte modificati")
    print("=" * 70)


def print_patch_details():
    """Stampa i dettagli di ogni patch"""
    for bf in BINARY_FILES:
        print(f"\n{'='*70}")
        print(f"FILE: {bf.name}")
        print(f"{'='*70}")

        for i, patch in enumerate(bf.patches, 1):
            print(f"\n--- Patch {i}/{len(bf.patches)} ---")
            print(patch)


def generate_patch_bytes():
    """
    Genera la rappresentazione delle patch in formato esadecimale
    utile per tool come hexedit o dd
    """
    print("\n" + "=" * 70)
    print("COMANDI PER APPLICARE PATCH MANUALMENTE (solo studio)")
    print("=" * 70)

    for bf in BINARY_FILES:
        print(f"\n# {bf.name}")
        for patch in bf.patches:
            # Formato per dd
            print(f"# {patch.description}")
            print(f"# Offset: {patch.offset} (0x{patch.offset:x})")
            hex_str = "\\x" + "\\x".join(f"{b:02x}" for b in patch.patched)
            print(f"# printf '{hex_str}' | dd of={bf.path} bs=1 seek={patch.offset} conv=notrunc")


# =============================================================================
# COSTANTI x86_64 (per riferimento)
# =============================================================================

X86_64_OPCODES = {
    # Istruzioni usate nelle patch
    "NOP": 0x90,
    "RET": 0xc3,
    "XOR_EAX_EAX": bytes([0x31, 0xc0]),  # xor eax, eax (imposta eax=0)
    "JMP_REL8": 0xeb,    # salto corto (8-bit offset)
    "JMP_REL32": 0xe9,   # salto lungo (32-bit offset)
    "JZ_REL8": 0x74,     # jump if zero (8-bit)
    "JNZ_REL8": 0x75,    # jump if not zero (8-bit)
    "JG_REL8": 0x7f,     # jump if greater (8-bit)
    "JL_REL32": bytes([0x0f, 0x8c]),  # jump if less (32-bit)
    "CALL_REL32": 0xe8,  # chiamata funzione (32-bit offset)
    "TEST_EAX_EAX": bytes([0x85, 0xc0]),  # test eax, eax
}

# Pattern comune: return 0 (3 byte)
RETURN_ZERO = bytes([0x31, 0xc0, 0xc3])  # xor eax, eax; ret


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import sys

    print(__doc__)

    if len(sys.argv) > 1:
        if sys.argv[1] == "--summary":
            print_patch_summary()
        elif sys.argv[1] == "--details":
            print_patch_details()
        elif sys.argv[1] == "--commands":
            generate_patch_bytes()
        elif sys.argv[1] == "--all":
            print_patch_summary()
            print_patch_details()
            generate_patch_bytes()
        else:
            print("Uso: python patch_analysis.py [--summary|--details|--commands|--all]")
    else:
        print_patch_summary()
        print("\nUsa --details per vedere i dettagli di ogni patch")
        print("Usa --commands per generare comandi dd")
        print("Usa --all per vedere tutto")
