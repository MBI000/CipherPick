import os, re
GUI_DIR = r'C:\Users\Mahmoud Basem\Desktop\CipherPick-V2\GUI'
def p(path):
    with open(path, 'r', encoding='utf-8') as f:
        c = f.read()
    def r(m):
        t = m.group(1)
        if t in ['...', '?', '-', '+']: return f'QPushButton("{t}")'
        if t.startswith('[') and t.endswith(']'): return m.group(0)
        return f'QPushButton("[ {t.upper()} ]")'
    nc = re.sub(r'QPushButton\("([^"]+)"\)', r, c)
    nc = re.sub(r"QPushButton\('([^']+)'\)", r, nc)
    if nc != c:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(nc)
        print('Updated', path)
for root, _, files in os.walk(GUI_DIR):
    for f in files:
        if f.endswith('.py'):
            p(os.path.join(root, f))
