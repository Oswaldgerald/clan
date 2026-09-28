(() => {
  const printButton = document.querySelector('[data-print-tree]');
  if (!printButton) return;

  printButton.addEventListener('click', () => {
    window.print();
  });
})();
