const params = new URLSearchParams(location.search);
document.getElementById("url").textContent = params.get("url") || "";
document.getElementById("why").textContent = (params.get("why") || "").replace(/,/g, ", ") || "unknown";
