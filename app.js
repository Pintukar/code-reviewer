const $ = (id) => document.getElementById(id);
const code = $("code");
code.addEventListener("input", () => {
  $("count").textContent = code.value.split("\n").length + " lines";
});
function el(tag, text, cls) {
  const e = document.createElement(tag);
  e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
$("go").addEventListener("click", async () => {
  $("err").textContent = "";
  $("go").disabled = true;
  try {
    const res = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: code.value }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Server error");
    render(data);
  } catch (e) {
    $("err").textContent = e.message || "Network error";
    $("result").hidden = true;
  } finally {
    $("go").disabled = false;
  }
});
function render(d) {
  $("result").hidden = false;
  const s = $("summary");
  s.replaceChildren(
    el("span", `High: ${d.summary.high}`, "pill high"),
    el("span", `Medium: ${d.summary.medium}`, "pill medium"),
    el("span", `Low: ${d.summary.low}`, "pill low"),
    el("span", `(${d.total_lines} lines)`, "pill")
  );
  const rows = $("rows");
  rows.replaceChildren();
  if (!d.issues.length) {
    const tr = document.createElement("tr");
    const td = el("td", "Koi issue nahi mila 🎉");
    td.colSpan = 5;
    tr.append(td);
    rows.append(tr);
  }
  for (const i of d.issues) {
    const tr = document.createElement("tr");
    const prob = document.createElement("td");
    prob.append(el("div", i.message), el("pre", i.code));
    tr.append(el("td", i.line), el("td", i.severity, i.severity), el("td", i.category), prob,
      (() => { const t = document.createElement("td"); t.append(el("pre", i.fix)); return t; })());
    rows.append(tr);
  }
  $("fixed").textContent = d.fixed_code;
  $("tests").textContent = d.test_suggestion || "Tests pehle se maujood hain ya koi function nahi mila.";
}