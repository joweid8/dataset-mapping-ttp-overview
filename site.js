const searchInput = document.querySelector("#matrix-search");
const clearButton = document.querySelector("#clear-search");
const columns = [...document.querySelectorAll(".matrix-column")];

function normalize(value) {
  return value.toLowerCase().trim();
}

function applyFilter() {
  const query = normalize(searchInput.value);
  columns.forEach((column) => {
    const headingText = normalize(column.querySelector(".tactic-heading").innerText);
    let visibleCards = 0;
    column.querySelectorAll(".technique-card").forEach((card) => {
      const matches = !query || headingText.includes(query) || normalize(card.innerText).includes(query);
      card.classList.toggle("is-hidden", !matches);
      if (matches) visibleCards += 1;
    });
    column.classList.toggle("is-hidden", query && visibleCards === 0 && !headingText.includes(query));
  });
}

if (searchInput && clearButton) {
  searchInput.addEventListener("input", applyFilter);
  clearButton.addEventListener("click", () => {
    searchInput.value = "";
    applyFilter();
    searchInput.focus();
  });
}
