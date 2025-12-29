import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import Handlebars from "handlebars";
import {
  parse as parseLicenseExpression,
  validate as validateLicenseExpression,
} from "license-expressions";

const CONFIG = {
  sbomPath: "compliance/sbom/traefik.cdx.json",
  licenseMapPath: "compliance/config/license-map.json",
  templates: {
    html: "compliance/templates/third_party_licenses.hbs",
    notice: "compliance/templates/notice.hbs",
  },
  outDir: "third_party",
  outLicensesDir: "third_party/licenses",
  customLicenseDir: "compliance/custom-license-texts",
  spdxVersion: "v3.27.0",
  ignore: {
    patterns: [
      /@[^@]*use\.local\b/i,
    ],
  },
};

const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));

const writeText = (p, s) => {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, s);
};

const fetchText = (url) =>
  new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": "oss-attributions-generator" } }, (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve(data));
      })
      .on("error", reject);
  });

async function loadSpdxNameMap() {
  const url = `https://raw.githubusercontent.com/spdx/license-list-data/${CONFIG.spdxVersion}/json/licenses.json`;
  const json = JSON.parse(await fetchText(url));
  const map = new Map();
  for (const lic of json.licenses || []) { map.set(lic.licenseId, lic.name); }
  return map;
}

async function getLicenseText(licenseId) {
  const cachedPath = path.join(CONFIG.outLicensesDir, `${licenseId}.txt`);
  if (fs.existsSync(cachedPath)) { return fs.readFileSync(cachedPath, "utf8"); }

  if (licenseId.startsWith("LicenseRef-")) {
    const customPath = path.join(CONFIG.customLicenseDir, `${licenseId}.txt`);
    if (!fs.existsSync(customPath)) {
      const msg = `Missing custom license text: ${customPath}`;
      writeText(cachedPath, msg);
      return msg;
    }
    const txt = fs.readFileSync(customPath, "utf8");;
    writeText(cachedPath, txt);
    return txt;
  }

  const url = `https://raw.githubusercontent.com/spdx/license-list-data/${CONFIG.spdxVersion}/text/${licenseId}.txt`;
  try {
    const txt = await fetchText(url);
    writeText(cachedPath, txt);
    return txt;
  } catch (e) {
    const msg = `Could not fetch SPDX text for ${licenseId} from ${url}\nError: ${e.message}\nMap it to a valid SPDX id or add a LicenseRef text.`;
    writeText(cachedPath, msg);
    return msg;
  }
}

function getLicensesRec(node, ids) {
  if (!node) return;
  if (node.license) {
    ids.push(node.license);
    return;
  }
  getLicensesRec(node.left, ids);
  getLicensesRec(node.right, ids);
}

function normalizeLicenseIds(licenses, licenseMap) {
  if (licenses?.length === 0) { return []; }

  const ids = [];
  for (const item of licenses) {
    if (item?.license?.id) {
      ids.push(item.license.id);
      continue;
    }

    const expr = item?.expression || item?.license?.name;
    if (!expr) { continue; }

    if (licenseMap[expr]) {
      ids.push(licenseMap[expr]);
      continue;
    }

    if (validateLicenseExpression(expr).valid) {
      const parsedExpr = parseLicenseExpression(expr, { upgradeGPLVariants: true });
      getLicensesRec(parsedExpr, ids);
    } else {
      ids.push(`LicenseRef-UNKNOWN-${expr.replace(/[^A-Za-z0-9]+/g, "-").slice(0, 40)}`);
    }
  }

  return [...new Set(ids)].sort();
}

function componentUrlFromPurl(purl) {
  if (!purl) return null;

  const m = purl.match(/^pkg:([^/]+)\/(.+)@([^@]+)$/);
  if (!m) return null;

  const [, type, nameRaw] = m;
  const name = decodeURIComponent(nameRaw);

  if (type === "npm") return `https://www.npmjs.com/package/${name}`;
  if (type === "pypi") return `https://pypi.org/project/${name}/`;
  if (type === "golang") {
    if (name.startsWith("github.com/")) {
      const parts = name.split("/");
      return `https://github.com/${parts[1]}/${parts[2]}`;
    }
    return `https://pkg.go.dev/${name}`;
  }

  return null;
}

function buildIndex(components, licenseMap) {
  const byLicense = new Map();
  const byPurl = new Map();

  for (const c of components) {
    if (CONFIG.ignore.patterns.some((p) => p.test(c.purl || ""))) { continue; }
    
    const licenseIds = normalizeLicenseIds(c.licenses, licenseMap);

    const comp = {
      name: c.name,
      version: c.version,
      purl: c.purl,
      url: componentUrlFromPurl(c.purl),
      licenseIds,
      copyright: c.copyright,
    };

    const existing = byPurl.get(c.purl);
    if (!existing) {
      byPurl.set(c.purl, comp);
    } else {
      existing.licenseIds = [...new Set([...existing.licenseIds, ...comp.licenseIds])].sort();
      if (!existing.copyright && comp.copyright) { existing.copyright = comp.copyright; }
    }

    for (const id of licenseIds) {
      const list = byLicense.get(id) || [];
      list.push(comp);
      byLicense.set(id, list);
    }
  }

  return { byLicense, byPurl };
}

async function main() {
  const [sbom, licenseMap, spdxNameMap] = await Promise.all([
    Promise.resolve(readJson(CONFIG.sbomPath)),
    Promise.resolve(readJson(CONFIG.licenseMapPath)),
    loadSpdxNameMap(),
  ]);

  const components = sbom.components || [];
  const { byLicense, byPurl } = buildIndex(components, licenseMap);

  fs.mkdirSync(CONFIG.outDir, { recursive: true });
  fs.mkdirSync(CONFIG.outLicensesDir, { recursive: true });

  const licenses = [];
  const sortedLicenseIds = [...byLicense.keys()].sort((a, b) => a.localeCompare(b));

  for (const id of sortedLicenseIds) {
    const comps = (byLicense.get(id) || []).slice().sort((a, b) =>
      (a.name + a.version).localeCompare(b.name + b.version)
    );

    const used_by = comps.map((component) => ({ component }));
    const name = spdxNameMap.get(id) || id;
    const text = await getLicenseText(id);

    licenses.push({ id, name, text, used_by });
  }

  const overview = licenses
    .map((l) => ({ id: l.id, name: l.name, count: l.used_by.length }))
    .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));

  const notices = [...byPurl.values()]
    .filter((c) => !!c.copyright)
    .sort((a, b) => (a.name + a.version).localeCompare(b.name + b.version));

  const model = {
    generatedAt: new Date().toISOString(),
    overview,
    licenses,
    notices,
  };

  const html = Handlebars.compile(fs.readFileSync(CONFIG.templates.html, "utf8"))(model);
  const notice = Handlebars.compile(fs.readFileSync(CONFIG.templates.notice, "utf8"))(model);

  writeText(path.join(CONFIG.outDir, "THIRD_PARTY_LICENSES.html"), html);
  writeText(path.join(CONFIG.outDir, "NOTICE.md"), notice);

  const unknowns = licenses.filter((l) => l.id.startsWith("LicenseRef-UNKNOWN-"));
  if (unknowns.length) {
    console.error("ERROR: Unknown license expressions found. Add mappings in compliance/config/license-map.json:");
    for (const u of unknowns) console.error(`- ${u.id}`);
    process.exitCode = 2;
  } else {
    console.log(
      `Wrote:\n- ${path.join(CONFIG.outDir, "THIRD_PARTY_LICENSES.html")}\n- ${path.join(
        CONFIG.outDir,
        "NOTICE.md"
      )}\n- ${path.join(CONFIG.outLicensesDir, "/")}`
    );
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
