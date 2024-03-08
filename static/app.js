document.addEventListener('DOMContentLoaded', function () {
    const scanTypeSelect = document.getElementById('scan_type');
    const specificPortDiv = document.getElementById('specific_port_div');
    const portRangeDiv = document.getElementById('port_range_div');

    scanTypeSelect.addEventListener('change', function () {
        if (this.value === '3') {
            specificPortDiv.style.display = 'block';
            portRangeDiv.style.display = 'none';
        } else if (this.value === '4') {
            specificPortDiv.style.display = 'none';
            portRangeDiv.style.display = 'block';
        } else {
            specificPortDiv.style.display = 'none';
            portRangeDiv.style.display = 'none';
        }
    });
});
