function body_onload() {
    let timeoutID = window.setTimeout(() => {
        let cover = document.getElementById('wrapper-sidebar-cover');
        cover.remove();
    }, 500);
}

