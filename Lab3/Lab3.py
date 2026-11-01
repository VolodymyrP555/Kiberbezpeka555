import sys
from collections import Counter         
from itertools import permutations      
from pathlib import Path

ALPHABET = list("абвгґдеєжзиіїйклмнопрстуфхцчшщьюя") + ["_", ",", ".", "-"]

FREQ_TABLE = {
    "о": 0.073, "а": 0.063, "и": 0.050, "н": 0.046, "в": 0.042, "і": 0.041,
    "е": 0.038, "т": 0.036, "р": 0.033, "с": 0.031, "л": 0.029, "у": 0.027,
    "к": 0.026, "д": 0.024, "м": 0.024, "п": 0.021, "я": 0.017, "з": 0.017,
    "б": 0.014, "ь": 0.013, "г": 0.013, "й": 0.011, "ч": 0.011, "х": 0.009,
    "ж": 0.007, "ш": 0.007, "ю": 0.007, "ц": 0.005, "щ": 0.005,
    "_": 0.154, ",": 0.021, ".": 0.013, "-": 0.006,
}

CRIBS = [
    ("тв", "не"), ("уд", "та"), ("д", "а"), ("щгт", "він"), ("сь_ь", "його"),
    ("цб", "як"), ("пь", "що"), ("кв", "же"), ("лл", "її"), ("доь", "або"),
    ("ьїг", "очі"), ("єьї", "хоч"), ("ьсш", "ой,"), ("я", "-"),
    ("идувег", "матері"), ("щигрд", "вміла"), ("ододююю", "баба..."),
    ("-ьог", "собі"), ("уьагю", "тоді."), ("нщмб", "звик"), ("рмжв", "лице"),
    ("ь_ьтф", "огонь"), (",ьїтв", "почне"), ("гтйд", "інша"),
    ("огсбьх", "бійкою"), ("о.щ", "був"), ("-єьщдіуф-ц", "сховається"),
]


def normalize(text: str) -> str:
    return text.strip("\n").replace(" ", "_").replace("–", "-")


def frequencies(text: str) -> list[tuple[str, int, float]]:
    counts = Counter(text)
    return [(ch, n, n / len(text)) for ch, n in counts.most_common()]


def frequency_guess(freqs) -> dict[str, str]:

    plain_by_rank = sorted(FREQ_TABLE, key=FREQ_TABLE.get, reverse=True)
    plain_by_rank += [c for c in ALPHABET if c not in plain_by_rank]
    return {c: plain_by_rank[i] for i, (c, _, _) in enumerate(freqs)}


def apply_cribs(space: str, cribs) -> dict[str, str]:
    mapping = {space: "_"}
    for cipher_word, plain_word in cribs:
        assert len(cipher_word) == len(plain_word), cipher_word
        for c, p in zip(cipher_word, plain_word):
            taken_by = next((k for k, v in mapping.items() if v == p), c)
            if mapping.get(c, p) != p or taken_by != c:
                raise ValueError(f"суперечність: {c}->{p} у '{cipher_word}'")
            mapping[c] = p
    return mapping


def build_key(mapping: dict[str, str]) -> dict[str, str]:

    key = {p: c for c, p in mapping.items()}
    missing_plain = [p for p in ALPHABET if p not in key]      
    missing_cipher = [c for c in ALPHABET if c not in mapping]  
    candidates = [key | dict(zip(missing_plain, perm))
                  for perm in permutations(missing_cipher)]
    return min(candidates, key=keyword_length)


def keyword_length(key: dict[str, str]) -> int:
    row = [key[p] for p in ALPHABET]  
    for start in range(len(row) + 1):
        if row[start:] == [c for c in ALPHABET if c not in row[:start]]:
            return start
    return len(row)


def keyword_part(key: dict[str, str]) -> str:
    row = [key[p] for p in ALPHABET]
    return "".join(row[:keyword_length(key)])


def decrypt(text: str, mapping: dict[str, str], unknown: str = "·") -> str:

    return "".join(mapping.get(c, unknown) for c in text).replace("_", " ")


def encrypt(text: str, key: dict[str, str]) -> str:
    return "".join(key[c] for c in text.replace(" ", "_"))


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "V12.txt")
    raw = path.read_text(encoding="utf-8")
    text = normalize(raw)

    print(f"Шифротекст: {path}, символів: {len(text)}\n")
    freqs = frequencies(text)
    plain_rank = sorted(FREQ_TABLE, key=FREQ_TABLE.get, reverse=True)
    print("Частоти шифротексту і таблиця 1:")
    for i, (c, n, f) in enumerate(freqs):
        ref = plain_rank[i] if i < len(plain_rank) else "?"
        print(f"  {c!r:5} {n:4} {f:.3f}   |  {ref!r:5} {FREQ_TABLE.get(ref, 0):.3f}")

    guess = frequency_guess(freqs)
    print("\nЕтап 1 - дешифрування лише за частотами (перші 300 символів):")
    print(decrypt(text, guess)[:300])

    mapping = apply_cribs(freqs[0][0], CRIBS)
    print(f"\nЕтап 2 - підказки визначили {len(mapping)} з {len(set(text))} символів шифру.")

    key = build_key(mapping)
    print(f"Етап 3 - відновлено таблицю: {keyword_length(key)} символів кодової фрази"
          f" + {len(ALPHABET) - keyword_length(key)} символів решти алфавіту.")

    inverse = {c: p for p, c in key.items()}
    plaintext = decrypt(text, inverse)

    assert encrypt(plaintext, key) == text, "повторне шифрування не збіглося"


    print("\nТаблиця підстановки (таблиця 2):")
    print(" ".join(ALPHABET))                   
    print(" ".join(key[p] for p in ALPHABET))    
    print(f"Унікальні символи кодової фрази: «{keyword_part(key).replace('_', ' ')}»")

    print("\nВідкритий текст:\n")
    print(plaintext)

    out = path.with_name(path.stem + "_decrypted.txt")
    out.write_text(plaintext + "\n", encoding="utf-8", newline="\n")

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
 
