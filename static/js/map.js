var state;

$(document).ready(function () {
    $('.map').each(function () {
        let lat = parseFloat($(this).attr('lat'));
        let long = parseFloat($(this).attr('long'));
        let map = L.map(this).setView([lat, long], 13);

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);

        L.marker([lat, long]).addTo(map)

        const config = { attributes: true, childList: true };

        const observer = new MutationObserver(function (mutations) {
            mutations.forEach(function (mutation) {
                map.invalidateSize();
            });
        });

        const carousel = $(this).parent().parent().parent()[0];
        observer.observe(carousel, config);

        $('.nav-link').click(function (e) {
            e.preventDefault();
            let id = $(this).attr('href').substring(1);
            let url = window.location.href.split('#')[0];
            history.replaceState(null, null, url + '#' + id);
            render(id);
            map.invalidateSize();

        });

        const url = new URL(window.location.href);
        if (url.hash !== '') {
            state = url.hash.substring(1);
        } else {
            state = 'summary';
        }

        render(state);
        map.invalidateSize();

    });
});

function render(id) {
    $(`#${state}`).attr('hidden', true);
    $(`#${id}`).attr('hidden', false);
    state = id;
}