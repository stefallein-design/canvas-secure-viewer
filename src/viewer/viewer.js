(async function () {
  const parts = window.location.pathname.split("/");
  const doc = parts[parts.length - 1];
  document.getElementById("doc").textContent = doc;

  const manifestRes = await fetch(`/api/docs/${encodeURIComponent(doc)}/manifest`, {
    credentials: "include",
  });

  if (!manifestRes.ok) {
    document.getElementById("pages").innerHTML =
      `<p>Kan manifest niet laden: ${manifestRes.status}</p>`;
    return;
  }

  const manifest = await manifestRes.json();
  const pagesEl = document.getElementById("pages");

  for (let i = 1; i <= manifest.pages; i++) {
    const img = document.createElement("img");
    img.loading = "lazy";
    img.alt = `Pagina ${i}`;
    img.src = `/api/docs/${encodeURIComponent(doc)}/page/${i}`;
    pagesEl.appendChild(img);
  }
})();
