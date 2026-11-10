// A small XML reader for AWS responses, so Edgewatch needs no XML dependency.
// AWS's Query and REST-XML APIs answer with plain element trees: no mixed
// content, no namespaces that matter, attributes that checks never read. That is
// all this handles.

export interface XmlNode {
  name: string;
  text: string;
  children: XmlNode[];
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
const decode = (s: string) =>
  s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) =>
    e[0] === "#" ? String.fromCodePoint(e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : (ENTITIES[e.toLowerCase()] ?? m),
  );

/** Parses a document into its root element. Throws on text that isn't XML. */
export function parseXml(src: string): XmlNode {
  const root: XmlNode = { name: "", text: "", children: [] };
  const stack = [root];
  const re = /<!\[CDATA\[([\s\S]*?)\]\]>|<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<\/([^\s>]+)\s*>|<([^\s/>]+)[^>]*?(\/?)>|([^<]+)/g;
  for (let m = re.exec(src); m; m = re.exec(src)) {
    const top = stack[stack.length - 1];
    if (m[1] != null) top.text += m[1];
    else if (m[2]) {
      if (stack.length > 1) stack.pop();
    } else if (m[3]) {
      const node: XmlNode = { name: m[3].replace(/^.*:/, ""), text: "", children: [] };
      top.children.push(node);
      if (!m[4]) stack.push(node);
    } else if (m[5]) top.text += decode(m[5]);
  }
  const doc = root.children[0];
  if (!doc) throw new Error("Not an XML document");
  return doc;
}

/** The first descendant along a path of element names, or undefined. */
export function at(node: XmlNode | undefined, ...path: string[]): XmlNode | undefined {
  let cur = node;
  for (const name of path) cur = cur?.children.find((c) => c.name === name);
  return cur;
}

/** The trimmed text at a path; null when the element is missing or empty. */
export function text(node: XmlNode | undefined, ...path: string[]): string | null {
  const t = at(node, ...path)?.text.trim();
  return t ? t : null;
}

/** The children of the list element at a path: `<Users><member/>…</Users>`, `<item>` for EC2, named elements for S3. */
export function items(node: XmlNode | undefined, ...path: string[]): XmlNode[] {
  return at(node, ...path)?.children ?? [];
}

/** "true"/"TRUE"/"1" → true, "false"/"0" → false, anything else (or missing) → null. */
export function bool(node: XmlNode | undefined, ...path: string[]): boolean | null {
  const t = text(node, ...path)?.toLowerCase();
  return t === "true" || t === "1" ? true : t === "false" || t === "0" ? false : null;
}

/** A timestamp in milliseconds, or null. */
export function time(node: XmlNode | undefined, ...path: string[]): number | null {
  const t = Date.parse(text(node, ...path) ?? "");
  return Number.isFinite(t) ? t : null;
}

/** The first descendant with this name, at any depth: the result element of a Query response, whatever wraps it. */
export function find(node: XmlNode | undefined, name: string): XmlNode | undefined {
  if (!node) return undefined;
  if (node.name === name) return node;
  for (const c of node.children) {
    const hit = find(c, name);
    if (hit) return hit;
  }
  return undefined;
}
