  const shell = document.querySelector(".tree-shell");
  const tree = document.querySelector("#tree");
  const loadedPeople = new Map();

  function avatarFor(person) {
    const avatar = document.createElement("span");
    avatar.className = "outline-avatar";
    if (person.photo_url) {
      const image = document.createElement("img");
      image.src = person.photo_url;
      image.alt = "";
      avatar.append(image);
    } else {
      avatar.textContent = person.name.split(/\s+/).slice(0, 2).map((part) => part[0]).join("");
    }

    return avatar;
  }

  async function fetchPerson(personId) {
    if (loadedPeople.has(personId)) return loadedPeople.get(personId);
    const response = await fetch(`${shell.dataset.endpoint}?root=${personId}&depth=1`);
    if (!response.ok) throw new Error("Tree request failed");
    const data = await response.json();
    loadedPeople.set(personId, data);
    return data;
  }

  function makeBranch(person, isRoot = false) {
    const item = document.createElement("li");
    item.className = "outline-item";
    const row = document.createElement("div");
    row.className = `outline-row${isRoot ? " is-root" : ""}`;

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "outline-toggle";
    toggle.textContent = "+";
    toggle.setAttribute("aria-label", `Expand ${person.name}`);
    toggle.setAttribute("aria-expanded", "false");

    const link = document.createElement("a");
    link.className = "outline-person";
    link.href = person.url;
    const copy = document.createElement("span");
    copy.className = "outline-copy";
    const name = document.createElement("strong");
    name.textContent = person.name;
    const meta = document.createElement("small");
    meta.textContent = `${person.member_id} · ${person.is_living ? "Living" : "Deceased"}`;
    copy.append(name, meta);
    if (person.other_parent) {
      const parentage = document.createElement("span");
      parentage.className = `outline-parentage${person.other_parent.different_union ? " is-different-union" : ""}${person.other_parent.missing ? " is-missing-parent" : ""}`;
      const parentLabel = document.createElement("span");
      parentLabel.textContent = `${person.other_parent.role}: ${person.other_parent.name}`;
      parentage.append(parentLabel);
      if (person.other_parent.different_union) {
        const marker = document.createElement("em");
        marker.textContent = "Different union";
        parentage.append(marker);
      } else if (person.other_parent.missing) {
        const marker = document.createElement("em");
        marker.textContent = "Not recorded";
        parentage.append(marker);
      }
      copy.append(parentage);
    }
    link.append(avatarFor(person), copy);

    const familyUnit = document.createElement("div");
    familyUnit.className = "outline-family-unit";
    if (person.other_parent?.different_union) familyUnit.classList.add("has-different-union");
    if (person.other_parent?.missing) familyUnit.classList.add("has-missing-parent");
    familyUnit.append(link);
    (person.spouses || []).forEach((spouse) => {
      const divider = document.createElement("span");
      divider.className = "outline-spouse-divider";
      divider.setAttribute("aria-hidden", "true");
      const spouseLink = document.createElement("a");
      spouseLink.className = "outline-spouse";
      spouseLink.href = spouse.url;
      const role = spouse.gender === "female" ? "Wife" : spouse.gender === "male" ? "Husband" : "Spouse";
      const roleLabel = document.createElement("small");
      roleLabel.textContent = role;
      const spouseName = document.createElement("strong");
      spouseName.textContent = spouse.name;
      spouseLink.append(roleLabel, spouseName);
      familyUnit.append(divider, spouseLink);
    });

    const childrenList = document.createElement("ul");
    childrenList.className = "outline-children";
    childrenList.hidden = true;
    row.append(toggle, familyUnit);
    item.append(row, childrenList);

    toggle.addEventListener("click", async () => {
      if (toggle.dataset.loading === "true") return;
      if (toggle.getAttribute("aria-expanded") === "true") {
        toggle.textContent = "+";
        toggle.setAttribute("aria-expanded", "false");
        toggle.setAttribute("aria-label", `Expand ${person.name}`);
        childrenList.hidden = true;
        return;
      }
      toggle.dataset.loading = "true";
      toggle.classList.add("is-loading");
      try {
        const data = await fetchPerson(person.id);
        if (!childrenList.childElementCount) {
          data.children.forEach((child) => childrenList.append(makeBranch(child)));
        }
        if (!data.children.length) {
          toggle.textContent = "·";
          toggle.classList.add("is-leaf");
          toggle.disabled = true;
          toggle.setAttribute("aria-label", `${person.name} has no recorded children`);
        } else {
          toggle.textContent = "−";
          toggle.setAttribute("aria-expanded", "true");
          toggle.setAttribute("aria-label", `Collapse ${person.name}`);
          childrenList.hidden = false;
        }
      } catch (error) {
        toggle.textContent = "+";
      } finally {
        toggle.dataset.loading = "false";
        toggle.classList.remove("is-loading");
      }
    });
    return item;
  }

  async function startTree() {
    const data = await fetchPerson(Number(shell.dataset.root));
    const list = document.createElement("ul");
    list.className = "outline-root";
    const rootBranch = makeBranch(data.person, true);
    list.append(rootBranch);
    tree.replaceChildren(list);
    rootBranch.querySelector(".outline-toggle").click();
  }

  function showError() {
    tree.textContent = "The family tree could not be loaded.";
  }
  startTree().catch(showError);
