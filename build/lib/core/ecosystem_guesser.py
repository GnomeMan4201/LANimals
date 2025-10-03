def guess_ecosystem(product_name):
    pname = product_name.lower()
    if "python" in pname or pname.endswith(".py"):
        return "PyPI"
    if "node" in pname or "npm" in pname or "javascript" in pname:
        return "npm"
    if "java" in pname or "tomcat" in pname or "spring" in pname:
        return "Maven"
    if "ruby" in pname or pname.endswith(".rb"):
        return "RubyGems"
    if "go" in pname:
        return "Go"
    if "rust" in pname:
        return "crates.io"
    return "Unknown"
