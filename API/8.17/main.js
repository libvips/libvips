// SPDX-FileCopyrightText: 2021 GNOME Foundation
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later
"use strict";


const urlMap = new Map(typeof baseURLs !== 'undefined' ? baseURLs : []);

window.addEventListener("hashchange", onDidHashChange);
window.addEventListener("load", onDidLoad, false);
window.addEventListener("keydown", onKeyDown);

function onDidLoad() {
    attachScrollHandlers()
    attachToggleHandlers()
    attachCopyHandlers()

    if (window.onInitSearch) {
        window.onInitSearch()
    }
}

function onDidHashChange() {
    // When URL fragment changes to ID of a collapsible section,
    // expand it when it is collapsed.
    // This is useful for clicking section links in the sidebar on the index page.
    const sectionHeader = document.querySelector(".section-header" + location.hash);
    if (sectionHeader !== null) {
        const parent = sectionHeader.parentNode;
        if (hasClass(parent, "toggle-wrapper")) {
            const toggle = parent.querySelector(".collapse-toggle");
            if (hasClass(toggle, "collapsed")) {
                toggle.click();
            }
        }
    }
}


function attachScrollHandlers() {
    const btnToTop = document.getElementById("btn-to-top");

    btnToTop.addEventListener('click', onClick);
    window.addEventListener('scroll', onScroll);

    function onClick(e) {
        e.preventDefault();
        window.scroll({ top: 0, behavior: 'smooth' });
    }

    function onScroll() {
        if (window.scrollY < 400) {
            addClass(btnToTop, "hidden");
        } else {
            removeClass(btnToTop, "hidden");
        }
    }
}

function attachToggleHandlers() {
    function label(isCollapsed) {
        return (
            "[<span class=\"inner\">" +
                (isCollapsed ? "+" : "\u2212") +
            "</span>]"
        )
    }

    function createToggle(isCollapsed) {
        const toggle = document.createElement("a");
        toggle.href = "javascript:void(0)";
        toggle.className = "collapse-toggle";
        toggle.innerHTML = label(isCollapsed);
        toggle.addEventListener('click', onClickToggle);
        return toggle;
    }

    function onClickToggle() {
        if (hasClass(this, "collapsed")) {
            removeClass(this, "collapsed");
            this.innerHTML = label(false);
            forEach(this.parentNode.querySelectorAll(".docblock"), function(e) {
                removeClass(e, "hidden");
            });
        } else {
            addClass(this, "collapsed");
            this.innerHTML = label(true);
            forEach(this.parentNode.querySelectorAll(".docblock"), function(e) {
                addClass(e, "hidden");
            });
        }
    }

    forEach(document.querySelectorAll(".toggle-wrapper"), function(e) {
        const sectionHeader = e.querySelector(".section-header");
        const fragmentMatches = sectionHeader !== null && location.hash === "#" + sectionHeader.getAttribute('id');
        const collapsedByDefault = hasClass(e, "default-hide") && !fragmentMatches;
        const toggle = createToggle(collapsedByDefault);
        e.insertBefore(toggle, e.firstChild);
        if (collapsedByDefault) {
            addClass(toggle, "collapsed");
            forEach(e.querySelectorAll(".docblock"), function(d) {
                addClass(d, "hidden");
            });
        }
    });

    function resolveNamespaceLink(namespace) {
        return urlMap.get(namespace);
    }

    forEach(document.querySelectorAll(".external"), function(e) {
        if (e.tagName == "A" && e.dataset.hasOwnProperty('namespace')) {
            var data_namespace = e.dataset.namespace
            var data_link = e.dataset.link
            var base_url = resolveNamespaceLink(data_namespace)
            if (base_url !== undefined) {
                e.href = base_url + data_link;
            } else {
                e.title = "No reference to the " + data_namespace + " namespace";
            }
        }
    })
}

function attachCopyHandlers() {
    if (!navigator.clipboard)
        return;

    forEach(document.querySelectorAll(".codehilite"), function(e) {
        const button = document.createElement("button");
        button.className = "copy-button";
        button.innerText = "Copy";
        button.title = "Copy code to clipboard";

        const text = e.innerText;
        button.addEventListener("click", () => {
            navigator.clipboard.writeText(text);
        });

        e.appendChild(button);
    })
}

function onKeyDown(event) {
    let search_input = document.querySelector("#search-input");
    // We don't want to try to focus the search input if it isn't visible. That way
    // we avoid the preventDefault(), hence allowing devhelp to use S as mnemonic.
    let potentially_hidden_parent = search_input.closest('.hidden, .devhelp-hidden');

    if (window.getComputedStyle(potentially_hidden_parent).display !== 'none') {
        if ((event.key === "s" || event.key === "S") &&
            document.activeElement !== search_input) {
            event.preventDefault();
            search_input.focus();
        } else if (event.key === "Escape" && document.activeElement === search_input) {
            if (window.hideResults) {
                window.hideResults();
            }
            search_input.value = "";
            search_input.blur();
        }
    }
}

// Helpers

function hasClass(elem, className) {
    return elem && elem.classList && elem.classList.contains(className);
}

function addClass(elem, className) {
    return elem && elem.classList && elem.classList.add(className);
}

function removeClass(elem, className) {
    return elem && elem.classList && elem.classList.remove(className);
}

function forEach(arr, func) {
    for (let i = 0; i < arr.length; ++i) {
        func(arr[i])
    }
}
