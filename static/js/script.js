// Funkcje wizualizacji ruchu sieciowego
document.addEventListener('DOMContentLoaded', function() {
    // Inicjalizacja wyszukiwania pakietów
    initPacketSearch();
    
    // Inicjalizacja wykresów, jeśli są dostępne dane
    if (document.getElementById('protocolChart')) {
        initCharts();
    }
    
    // Inicjalizacja interfejsu generowania raportów, jeśli jest dostępny
    if (document.getElementById('generateReportBtn')) {
        initReportGenerator();
    }
    
    // Inicjalizacja zaawansowanego podglądu pakietów
    initAdvancedPacketViewer();
    
    // Inicjalizacja funkcjonalności filtrowanego raportu
    initFilteredReportGenerator();
});

// Wyszukiwanie pakietów
function initPacketSearch() {
    const searchInput = document.getElementById('packetSearch');
    if (!searchInput) return;
    
    searchInput.addEventListener('input', function(e) {
        const searchTerm = e.target.value.toLowerCase();
        const packetItems = document.querySelectorAll('.packet-item');
        
        packetItems.forEach(item => {
            const text = item.textContent.toLowerCase();
            if (text.includes(searchTerm)) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });
    });
}

// Inicjalizacja wykresów
function initCharts() {
    // Wykres protokołów
    if (document.getElementById('protocolChart')) {
        initProtocolChart();
    }
    
    // Wykres portów
    if (document.getElementById('portChart')) {
        initPortChart();
    }
    
    // Wykres czasowy
    if (document.getElementById('timeChart')) {
        initTimeChart();
    }
    
    // Wykres wielkości pakietów
    if (document.getElementById('packetSizeChart')) {
        initPacketSizeChart();
    }
    
    // Wykres komunikacji między hostami (sieć)
    if (document.getElementById('networkGraph')) {
        initNetworkGraph();
    }
    
    // Mapa geograficzna IP (jeśli dostępne dane geolokalizacyjne)
    if (document.getElementById('geoMap')) {
        initGeoMap();
    }
}

// Wykres protokołów (Pie Chart)
function initProtocolChart() {
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    const protocolData = JSON.parse(document.getElementById('protocolData').textContent);
    
    new Chart(protocolCtx, {
        type: 'pie',
        data: {
            labels: Object.keys(protocolData),
            datasets: [{
                data: Object.values(protocolData),
                backgroundColor: [
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 99, 132, 0.7)',
                    'rgba(255, 206, 86, 0.7)',
                    'rgba(75, 192, 192, 0.7)',
                    'rgba(153, 102, 255, 0.7)',
                    'rgba(255, 159, 64, 0.7)',
                    'rgba(201, 203, 207, 0.7)'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Rozkład protokołów'
                },
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

// Wykres portów (Bar Chart)
function initPortChart() {
    const portCtx = document.getElementById('portChart').getContext('2d');
    const portData = JSON.parse(document.getElementById('portData').textContent);
    
    const ports = portData.map(item => `Port ${item.port}`);
    const counts = portData.map(item => item.count);
    
    new Chart(portCtx, {
        type: 'bar',
        data: {
            labels: ports,
            datasets: [{
                label: 'Liczba pakietów',
                data: counts,
                backgroundColor: 'rgba(54, 162, 235, 0.7)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Liczba pakietów'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Numery portów'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Najczęściej używane porty'
                }
            }
        }
    });
}

// Wykres czasowy ruchu (Line Chart)
function initTimeChart() {
    const timeCtx = document.getElementById('timeChart').getContext('2d');
    const timeData = JSON.parse(document.getElementById('timeData').textContent);
    
    new Chart(timeCtx, {
        type: 'line',
        data: {
            labels: timeData.labels,
            datasets: [{
                label: 'Liczba pakietów',
                data: timeData.values,
                borderColor: 'rgba(75, 192, 192, 1)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderWidth: 2,
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Liczba pakietów'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Czas'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Rozkład czasowy ruchu'
                }
            }
        }
    });
}

// Wykres wielkości pakietów (Histogram)
function initPacketSizeChart() {
    const sizeCtx = document.getElementById('packetSizeChart').getContext('2d');
    const sizeData = JSON.parse(document.getElementById('packetSizeData').textContent);
    
    new Chart(sizeCtx, {
        type: 'bar',
        data: {
            labels: sizeData.labels,
            datasets: [{
                label: 'Liczba pakietów',
                data: sizeData.values,
                backgroundColor: 'rgba(255, 99, 132, 0.7)',
                borderColor: 'rgba(255, 99, 132, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Liczba pakietów'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Wielkość pakietu (bajty)'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Rozkład wielkości pakietów'
                }
            }
        }
    });
}

// Graf komunikacji między hostami
function initNetworkGraph() {
    const networkContainer = document.getElementById('networkGraph');
    const networkData = JSON.parse(document.getElementById('networkData').textContent);
    
    // Wykorzystanie biblioteki vis.js do wizualizacji grafu
    const nodes = new vis.DataSet(networkData.nodes);
    const edges = new vis.DataSet(networkData.edges);
    
    const data = { nodes, edges };
    const options = {
        nodes: {
            shape: 'dot',
            scaling: {
                min: 10,
                max: 30,
                label: {
                    min: 8,
                    max: 30,
                    drawThreshold: 8,
                    maxVisible: 20
                }
            },
            font: {
                size: 12,
                face: 'Tahoma'
            }
        },
        edges: {
            width: 0.15,
            color: { inherit: 'from' },
            smooth: {
                type: 'continuous'
            }
        },
        physics: {
            stabilization: false,
            barnesHut: {
                gravitationalConstant: -80000,
                springConstant: 0.001,
                springLength: 200
            }
        },
        interaction: {
            tooltipDelay: 200,
            hideEdgesOnDrag: true
        }
    };
    
    new vis.Network(networkContainer, data, options);
}

// Mapa geolokalizacyjna IP
function initGeoMap() {
    const geoContainer = document.getElementById('geoMap');
    const geoData = JSON.parse(document.getElementById('geoData').textContent);
    
    // Inicjalizacja mapy leaflet
    const map = L.map(geoContainer).setView([0, 0], 2);
    
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);
    
    // Dodawanie znaczników dla lokalizacji IP
    geoData.forEach(location => {
        if (location.lat && location.lon) {
            L.marker([location.lat, location.lon])
                .addTo(map)
                .bindPopup(`<b>IP:</b> ${location.ip}<br><b>Kraj:</b> ${location.country}<br><b>Miasto:</b> ${location.city}<br><b>Pakiety:</b> ${location.packets}`);
        }
    });
}

// Zaawansowany podgląd pakietów
function initAdvancedPacketViewer() {
    // Inicjalizacja komponentu DataTables dla tabeli pakietów (jeśli istnieje)
    if (document.getElementById('packetsTable')) {
        $('#packetsTable').DataTable({
            pageLength: 25,
            order: [[0, 'asc']],
            responsive: true,
            columnDefs: [
                { responsivePriority: 1, targets: 0 },
                { responsivePriority: 2, targets: 1 },
                { responsivePriority: 3, targets: 2 }
            ]
        });
    }
    
    // Obsługa podglądu szczegółów pakietu
    const packetDetails = document.querySelectorAll('.packet-details-btn');
    packetDetails.forEach(btn => {
        btn.addEventListener('click', function() {
            const packetId = this.getAttribute('data-packet-id');
            const packetData = JSON.parse(document.getElementById(`packet-data-${packetId}`).textContent);
            
            // Wypełnianie modalu danymi pakietu
            document.getElementById('packetModalLabel').textContent = `Pakiet #${packetId}`;
            
            // Formatowanie JSON do wyświetlenia
            document.getElementById('packetModalBody').innerHTML = `
                <div class="packet-tabs">
                    <ul class="nav nav-tabs" id="packetTab" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" id="summary-tab" data-bs-toggle="tab" data-bs-target="#summary" type="button" role="tab">Podsumowanie</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip" type="button" role="tab">IP</button>
                        </li>
                        ${packetData.tcp ? `
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="tcp-tab" data-bs-toggle="tab" data-bs-target="#tcp" type="button" role="tab">TCP</button>
                            </li>
                        ` : ''}
                        ${packetData.udp ? `
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="udp-tab" data-bs-toggle="tab" data-bs-target="#udp" type="button" role="tab">UDP</button>
                            </li>
                        ` : ''}
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="raw-tab" data-bs-toggle="tab" data-bs-target="#raw" type="button" role="tab">Raw</button>
                        </li>
                    </ul>
                    <div class="tab-content" id="packetTabContent">
                        <div class="tab-pane fade show active" id="summary" role="tabpanel">
                            <table class="table">
                                <tr><th>Numer pakietu</th><td>${packetData.packet_number}</td></tr>
                                <tr><th>Czas</th><td>${packetData.time}</td></tr>
                                <tr><th>Długość</th><td>${packetData.length} bajtów</td></tr>
                                ${packetData.ip ? `
                                <tr><th>Źródło</th><td>${packetData.ip.src}</td></tr>
                                <tr><th>Cel</th><td>${packetData.ip.dst}</td></tr>
                                ` : ''}
                            </table>
                        </div>
                        ${packetData.ip ? `
                        <div class="tab-pane fade" id="ip" role="tabpanel">
                            <table class="table">
                                <tr><th>Źródło</th><td>${packetData.ip.src}</td></tr>
                                <tr><th>Cel</th><td>${packetData.ip.dst}</td></tr>
                                <tr><th>Protokół</th><td>${packetData.ip.proto}</td></tr>
                                <tr><th>TTL</th><td>${packetData.ip.ttl}</td></tr>
                            </table>
                        </div>
                        ` : ''}
                        ${packetData.tcp ? `
                        <div class="tab-pane fade" id="tcp" role="tabpanel">
                            <table class="table">
                                <tr><th>Port źródłowy</th><td>${packetData.tcp.sport}</td></tr>
                                <tr><th>Port docelowy</th><td>${packetData.tcp.dport}</td></tr>
                                <tr><th>Flagi</th><td>${packetData.tcp.flags}</td></tr>
                                <tr><th>Sekwencja</th><td>${packetData.tcp.seq}</td></tr>
                                <tr><th>Potwierdzenie</th><td>${packetData.tcp.ack}</td></tr>
                            </table>
                        </div>
                        ` : ''}
                        ${packetData.udp ? `
                        <div class="tab-pane fade" id="udp" role="tabpanel">
                            <table class="table">
                                <tr><th>Port źródłowy</th><td>${packetData.udp.sport}</td></tr>
                                <tr><th>Port docelowy</th><td>${packetData.udp.dport}</td></tr>
                                <tr><th>Długość</th><td>${packetData.udp.len}</td></tr>
                            </table>
                        </div>
                        ` : ''}
                        <div class="tab-pane fade" id="raw" role="tabpanel">
                            <pre>${JSON.stringify(packetData, null, 2)}</pre>
                        </div>
                    </div>
                </div>
            `;
            
            // Otwieranie modalu
            const packetModal = new bootstrap.Modal(document.getElementById('packetModal'));
            packetModal.show();
        });
    });
}

// Generator raportów PDF
function initReportGenerator() {
    const reportBtn = document.getElementById('generateReportBtn');
    if (!reportBtn) return;
    
    reportBtn.addEventListener('click', function() {
        // Przygotowanie modalu z opcjami raportu
        const reportModal = new bootstrap.Modal(document.getElementById('reportModal'));
        reportModal.show();
    });
    
    // Obsługa przycisku "Zaznacz wszystko"
    document.getElementById('selectAllBtn').addEventListener('click', function() {
        const checkboxes = document.querySelectorAll('#reportOptions input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            checkbox.checked = true;
        });
    });
    
    // Obsługa przycisku "Odznacz wszystko"
    document.getElementById('deselectAllBtn').addEventListener('click', function() {
        const checkboxes = document.querySelectorAll('#reportOptions input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            checkbox.checked = false;
        });
    });
    
    // Obsługa formularza generowania raportu
    document.getElementById('generateReportForm').addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Zbieranie zaznaczonych opcji
        const options = [];
        document.querySelectorAll('#reportOptions input[type="checkbox"]:checked').forEach(checkbox => {
            options.push(checkbox.value);
        });
        
        if (options.length === 0) {
            alert('Zaznacz co najmniej jedną opcję do wygenerowania raportu.');
            return;
        }
        
        // Zamknięcie modalu
        bootstrap.Modal.getInstance(document.getElementById('reportModal')).hide();
        
        // Ręczne przekierowanie z parametrami
        const params = new URLSearchParams();
        options.forEach(option => {
            params.append('options[]', option);
        });
        
        // Przekierowanie do endpointu generującego PDF
        window.location.href = `/generate_report/${filename}?${params.toString()}`;
    });
}

// Generator filtrowanych raportów
function initFilteredReportGenerator() {
    const filteredReportBtn = document.getElementById('generateFilteredReportBtn');
    if (!filteredReportBtn) return;
    
    // Obsługa kliknięcia przycisku "Raport z filtrów"
    filteredReportBtn.addEventListener('click', function() {
        // Pobieranie wartości filtrów
        const srcIp = document.getElementById('filter-src-ip').value;
        const dstIp = document.getElementById('filter-dst-ip').value;
        const protocol = document.getElementById('filter-protocol').value;
        const port = document.getElementById('filter-port').value;
        const lengthMin = document.getElementById('filter-length-min').value;
        const lengthMax = document.getElementById('filter-length-max').value;
        const timeStart = document.getElementById('filter-time-start').value;
        const timeEnd = document.getElementById('filter-time-end').value;
        
        // Przygotowanie danych do wysłania
        const filterData = {
            srcIp: srcIp,
            dstIp: dstIp,
            protocol: protocol,
            port: port,
            lengthMin: lengthMin,
            lengthMax: lengthMax,
            timeStart: timeStart,
            timeEnd: timeEnd
        };
        
        // Wyświetlenie informacji o trwającym generowaniu
        filteredReportBtn.disabled = true;
        filteredReportBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generowanie...';
        
        // Wysłanie żądania do serwera
        fetch(`/generate_filtered_report/${filename}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(filterData)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Przywrócenie przycisku
            filteredReportBtn.disabled = false;
            filteredReportBtn.innerHTML = '<i class="fas fa-file-pdf"></i> Raport z filtrów';
            
            if (data.success) {
                // Przekierowanie do pobrania wygenerowanego raportu
                window.location.href = data.report_url;
            } else {
                alert(`Błąd generowania raportu: ${data.error}`);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            // Przywrócenie przycisku
            filteredReportBtn.disabled = false;
            filteredReportBtn.innerHTML = '<i class="fas fa-file-pdf"></i> Raport z filtrów';
            alert('Wystąpił błąd podczas generowania raportu. Sprawdź konsolę przeglądarki.');
        });
    });
    
    // Obsługa przycisku "Zastosuj filtry"
    const applyFiltersBtn = document.getElementById('apply-filters');
    if (applyFiltersBtn) {
        applyFiltersBtn.addEventListener('click', function() {
            // Tutaj można dodać kod do filtrowania tabeli bez generowania raportu PDF
            // Na przykład filtrowanie w DataTables
            
            // Pobieranie wartości filtrów
            const srcIp = document.getElementById('filter-src-ip').value.toLowerCase();
            const dstIp = document.getElementById('filter-dst-ip').value.toLowerCase();
            const protocol = document.getElementById('filter-protocol').value;
            const port = document.getElementById('filter-port').value;
            const lengthMin = parseInt(document.getElementById('filter-length-min').value) || 0;
            const lengthMax = parseInt(document.getElementById('filter-length-max').value) || Number.MAX_SAFE_INTEGER;
            
            // Zastosowanie niestandardowego filtra do DataTables
            const dataTable = $('#packetsTable').DataTable();
            
            // Własny filtr wyszukiwania
            $.fn.dataTable.ext.search.push(
                function(settings, data, dataIndex) {
                    // Indeksy kolumn w tabeli
                    const srcIdx = 2; // Źródło IP
                    const dstIdx = 3; // Cel IP
                    const protoIdx = 4; // Protokół
                    const portsIdx = 5; // Porty
                    const lengthIdx = 6; // Długość
                    
                    // Dane z wiersza
                    const rowSrc = data[srcIdx].toLowerCase();
                    const rowDst = data[dstIdx].toLowerCase();
                    const rowProto = data[protoIdx];
                    const rowPorts = data[portsIdx];
                    const rowLength = parseInt(data[lengthIdx]) || 0;
                    
                    // Sprawdzanie warunków filtrowania
                    let match = true;
                    
                    if (srcIp && !rowSrc.includes(srcIp)) match = false;
                    if (dstIp && !rowDst.includes(dstIp)) match = false;
                    if (protocol && rowProto !== protocol) match = false;
                    if (port && !rowPorts.includes(port)) match = false;
                    if (rowLength < lengthMin || rowLength > lengthMax) match = false;
                    
                    return match;
                }
            );
            
            // Przeładowanie tabeli z uwzględnieniem filtrów
            dataTable.draw();
            
            // Usunięcie filtra po zastosowaniu
            $.fn.dataTable.ext.search.pop();
        });
    }
    
    // Obsługa przycisku "Resetuj filtry"
    const resetFiltersBtn = document.getElementById('reset-filters');
    if (resetFiltersBtn) {
        resetFiltersBtn.addEventListener('click', function() {
            // Czyszczenie pól filtrów
            document.getElementById('filter-src-ip').value = '';
            document.getElementById('filter-dst-ip').value = '';
            document.getElementById('filter-protocol').value = '';
            document.getElementById('filter-port').value = '';
            document.getElementById('filter-length-min').value = '';
            document.getElementById('filter-length-max').value = '';
            document.getElementById('filter-time-start').value = '';
            document.getElementById('filter-time-end').value = '';
            
            // Przywrócenie oryginalnej tabeli
            $('#packetsTable').DataTable().search('').columns().search('').draw();
        });
    }
}