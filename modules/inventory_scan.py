import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))
#!/usr/bin/env python3
import os
from pathlib import Path
from rich.console import Console
from rich.tree import Tree
from rich.text import Text

console = Console()
root_path = Path(__file__).resolve().parent

def build_tree(path: Path, tree: Tree):
    try:
        entries = sorted(path.iterdir(), key=lambda e: (e.is_file(), e.name.lower()))
    except PermissionError:
        return

    for entry in entries:
        label = Text(entry.name)
        if entry.is_dir():
            branch = tree.add(label + Text(" [dir]", style="bold red"))
            build_tree(entry, branch)
        elif entry.is_symlink():
            label.stylize("bold magenta")
            try:
                label.append(" → " + str(entry.resolve()))
            except:
                label.append(" [broken]")
                label.stylize("bold red")
            tree.add(label)
        elif entry.is_file():
            label.stylize("white")
            tree.add(label)

tree = Tree(f":package: [bold green]LANimals Inventory – {root_path.name}")
build_tree(root_path, tree)
console.print(tree)


if __name__ == '__main__':
    main()
