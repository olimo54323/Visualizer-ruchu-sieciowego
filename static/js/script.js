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

    if (document.getElementById('networkMetricsDisplay')) {
        displayNetworkMetrics();
    }
    
    // Inicjalizacja zaawansowanego podglądu pakietów
    initAdvancedPacketViewer();
    
    // Inicjalizacja funkcjonalności filtrowanego raportu
    initFilteredReportGenerator();

    window.dispatchEvent(new Event('resize'));
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
    
    // Wykres adresów MAC
    if (document.getElementById('macChart')) {
        initMacChart();
    }
    
    // Wykres producentów MAC
    if (document.getElementById('vendorChart')) {
        initVendorChart();
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
   
   // Wykres komunikacji między adresami MAC
   if (document.getElementById('macGraph')) {
       initMacGraph();
   }
   
   // Mapa geograficzna IP (jeśli dostępne dane geolokalizacyjne)
   if (document.getElementById('geoMap')) {
       initGeoMap();
   }
   if (document.getElementById('payloadChart')) {
        initPayloadChart();
    }
    
    if (document.getElementById('throughputChart')) {
        initThroughputChart();
    }
    
    if (document.getElementById('protocolPayloadChart')) {
        initProtocolPayloadChart();
    }
    
    if (document.getElementById('networkEfficiencyChart')) {
        initNetworkEfficiencyChart();
    }
    
    // Ulepszony graf MAC z protokołami
    if (document.getElementById('enhancedMacGraph')) {
        initEnhancedMacGraph();
    }
}

function initPayloadChart() {
    const payloadCtx = document.getElementById('payloadChart').getContext('2d');
    const payloadData = JSON.parse(document.getElementById('payloadStatsData').textContent);
    
    const chartData = {
        labels: ['Średni Payload', 'Max Payload', 'Min Payload'],
        datasets: [{
            label: 'Bajty',
            data: [
                payloadData.avg_payload_per_packet,
                payloadData.max_payload_size,
                payloadData.min_payload_size
            ],
            backgroundColor: [
                'rgba(54, 162, 235, 0.7)',
                'rgba(255, 99, 132, 0.7)',
                'rgba(255, 206, 86, 0.7)'
            ],
            borderColor: [
                'rgba(54, 162, 235, 1)',
                'rgba(255, 99, 132, 1)',
                'rgba(255, 206, 86, 1)'
            ],
            borderWidth: 1
        }]
    };
    
    new Chart(payloadCtx, {
        type: 'bar',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Bajty'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Statystyki Payload'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.dataset.label}: ${context.parsed.y.toFixed(2)} bajtów`;
                        }
                    }
                }
            }
        }
    });
}

// Wykres throughput w czasie
function initThroughputChart() {
    const throughputCtx = document.getElementById('throughputChart').getContext('2d');
    const throughputData = JSON.parse(document.getElementById('throughputStatsData').textContent);
    
    new Chart(throughputCtx, {
        type: 'line',
        data: {
            labels: throughputData.time_labels,
            datasets: [{
                label: 'Bajty/sekunda',
                data: throughputData.bytes_per_second,
                borderColor: 'rgba(75, 192, 192, 1)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderWidth: 2,
                tension: 0.1,
                fill: true,
                yAxisID: 'y'
            }, {
                label: 'Pakiety/sekunda',
                data: throughputData.packets_per_second,
                borderColor: 'rgba(255, 99, 132, 1)',
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderWidth: 2,
                tension: 0.1,
                fill: false,
                yAxisID: 'y1'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Throughput w czasie'
                },
                legend: {
                    display: true
                }
            },
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Czas'
                    }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Bajty/sekunda'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Pakiety/sekunda'
                    },
                    grid: {
                        drawOnChartArea: false,
                    },
                }
            }
        }
    });
}

// Wykres payload per protocol
function initProtocolPayloadChart() {
    const protocolPayloadCtx = document.getElementById('protocolPayloadChart').getContext('2d');
    const protocolPayloadData = JSON.parse(document.getElementById('protocolPayloadData').textContent);
    
    const protocols = Object.keys(protocolPayloadData);
    const payloadTotals = protocols.map(proto => protocolPayloadData[proto].total);
    const avgPayloads = protocols.map(proto => 
        protocolPayloadData[proto].packets > 0 ? 
        protocolPayloadData[proto].total / protocolPayloadData[proto].packets : 0
    );
    
    new Chart(protocolPayloadCtx, {
        type: 'bar',
        data: {
            labels: protocols,
            datasets: [{
                label: 'Całkowity Payload (bajty)',
                data: payloadTotals,
                backgroundColor: 'rgba(54, 162, 235, 0.7)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1,
                yAxisID: 'y'
            }, {
                label: 'Średni Payload na pakiet (bajty)',
                data: avgPayloads,
                backgroundColor: 'rgba(255, 159, 64, 0.7)',
                borderColor: 'rgba(255, 159, 64, 1)',
                borderWidth: 1,
                yAxisID: 'y1'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Payload według protokołów'
                }
            },
            scales: {
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Całkowity Payload (bajty)'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Średni Payload (bajty)'
                    },
                    grid: {
                        drawOnChartArea: false,
                    }
                }
            }
        }
    });
}

// Wykres efektywności sieci
function initNetworkEfficiencyChart() {
    const efficiencyCtx = document.getElementById('networkEfficiencyChart').getContext('2d');
    const networkLoadData = JSON.parse(document.getElementById('networkLoadData').textContent);
    
    const payloadBytes = networkLoadData.total_bytes - networkLoadData.header_overhead;
    
    new Chart(efficiencyCtx, {
        type: 'doughnut',
        data: {
            labels: ['Payload (Dane użyteczne)', 'Nagłówki (Overhead)'],
            datasets: [{
                data: [payloadBytes, networkLoadData.header_overhead],
                backgroundColor: [
                    'rgba(75, 192, 192, 0.7)',
                    'rgba(255, 99, 132, 0.7)'
                ],
                borderColor: [
                    'rgba(75, 192, 192, 1)',
                    'rgba(255, 99, 132, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: `Efektywność sieci: ${networkLoadData.payload_efficiency.toFixed(1)}%`
                },
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.parsed * 100) / total).toFixed(1);
                            return `${context.label}: ${context.parsed.toLocaleString()} bajtów (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Ulepszony graf komunikacji MAC z protokołami
function initEnhancedMacGraph() {
    const macContainer = document.getElementById('enhancedMacGraph');
    const macData = JSON.parse(document.getElementById('enhancedMacGraphData').textContent);
    
    // Przygotowanie węzłów z kolorami protokołów
    const nodes = new vis.DataSet(macData.nodes.map(node => ({
        ...node,
        color: {
            background: node.color,
            border: '#000000',
            highlight: {
                background: node.color,
                border: '#ff0000'
            }
        },
        font: {
            color: '#000000',
            size: 12
        },
        shape: 'dot',
        size: Math.max(10, Math.min(50, node.value / 10))
    })));
    
    const edges = new vis.DataSet(macData.edges.map(edge => ({
        ...edge,
        width: Math.max(1, Math.min(10, edge.value / 5)),
        color: {
            color: '#848484',
            highlight: '#ff0000'
        },
        smooth: {
            type: 'continuous'
        }
    })));
    
    const data = { nodes, edges };
    const options = {
        nodes: {
            borderWidth: 2,
            shadow: true
        },
        edges: {
            arrows: {
                to: { enabled: true, scaleFactor: 1 }
            },
            shadow: true
        },
        physics: {
            enabled: true,
            barnesHut: {
                gravitationalConstant: -8000,
                centralGravity: 0.3,
                springLength: 95,
                springConstant: 0.04,
                damping: 0.09
            },
            stabilization: {
                iterations: 100
            }
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            selectConnectedEdges: false
        }
    };
    
    const network = new vis.Network(macContainer, data, options);
    
    // Dodanie legendy protokołów
    const legendContainer = document.createElement('div');
    legendContainer.style.cssText = `
        position: absolute;
        top: 10px;
        right: 10px;
        background: rgba(255, 255, 255, 0.9);
        padding: 10px;
        border-radius: 5px;
        border: 1px solid #ccc;
        font-size: 12px;
    `;
    
    const protocolColors = {
        'TCP': '#FF6B6B',
        'UDP': '#4ECDC4',
        'ICMP': '#45B7D1',
        'ARP': '#96CEB4',
        'DNS': '#FECA57',
        'HTTP': '#FF9FF3',
        'HTTPS': '#54A0FF',
        'Unknown': '#DDA0DD'
    };
    
    let legendHTML = '<strong>Protokoły:</strong><br>';
    Object.entries(protocolColors).forEach(([protocol, color]) => {
        legendHTML += `<div style="margin: 2px 0;"><span style="display: inline-block; width: 12px; height: 12px; background: ${color}; margin-right: 5px; border-radius: 50%;"></span>${protocol}</div>`;
    });
    
    legendContainer.innerHTML = legendHTML;
    macContainer.style.position = 'relative';
    macContainer.appendChild(legendContainer);
    
    // Event listener dla wyświetlania szczegółów węzła
    network.on("selectNode", function (params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const nodeData = nodes.get(nodeId);
            
            if (nodeData && nodeData.protocol_stats) {
                let protocolInfo = '<strong>Statystyki protokołów:</strong><br>';
                Object.entries(nodeData.protocol_stats).forEach(([protocol, count]) => {
                    protocolInfo += `${protocol}: ${count} pakietów<br>`;
                });
                
                // Można tu dodać modal lub tooltip z dodatkowymi informacjami
                console.log('Node details:', protocolInfo);
            }
        }
    });
}

// Dodaj funkcję do wyświetlania metryk w interface
function displayNetworkMetrics() {
    // Funkcja może być wywołana do wyświetlenia podsumowania metryk
    try {
        const payloadStats = JSON.parse(document.getElementById('payloadStatsData').textContent);
        const throughputStats = JSON.parse(document.getElementById('throughputStatsData').textContent);
        const networkLoad = JSON.parse(document.getElementById('networkLoadData').textContent);
        
        const metricsContainer = document.getElementById('networkMetricsDisplay');
        if (metricsContainer) {
            metricsContainer.innerHTML = `
                <div class="row">
                    <div class="col-md-3">
                        <div class="card">
                            <div class="card-body text-center">
                                <h5>Całkowity Payload</h5>
                                <h3 class="text-primary">${(payloadStats.total_payload_bytes / 1024 / 1024).toFixed(2)} MB</h3>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card">
                            <div class="card-body text-center">
                                <h5>Średni Throughput</h5>
                                <h3 class="text-success">${(throughputStats.avg_throughput / 1024).toFixed(2)} KB/s</h3>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card">
                            <div class="card-body text-center">
                                <h5>Peak Throughput</h5>
                                <h3 class="text-warning">${(throughputStats.peak_throughput / 1024).toFixed(2)} KB/s</h3>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card">
                            <div class="card-body text-center">
                                <h5>Efektywność</h5>
                                <h3 class="text-info">${networkLoad.payload_efficiency.toFixed(1)}%</h3>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error displaying network metrics:', error);
    }
}

window.addEventListener('resize', function() {
    // Aktualizacja wysokości kontenerów wykresów
    const chartContainers = document.querySelectorAll('.chart-container');
    const windowHeight = window.innerHeight;
    
    chartContainers.forEach(container => {
        // Ustaw wysokość kontenera na procent wysokości okna
        const newHeight = Math.max(250, windowHeight * 0.3); // Minimum 250px, maksymalnie 30% wysokości okna
        container.style.height = `${newHeight}px`;
    });
});

// Wykres protokołów (Pie Chart)
function initProtocolChart() {
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    const protocolData = JSON.parse(document.getElementById('protocolData').textContent);
    
    // Konfiguracja z lepszym zarządzaniem responsywnością
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
                    text: 'Rozkład protokołów',
                    font: {
                        size: 16
                    }
                },
                legend: {
                    position: 'right',
                    labels: {
                        boxWidth: 15,
                        font: {
                            size: 12
                        }
                    }
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

// Wykres adresów MAC (Bar Chart)
function initMacChart() {
   const macCtx = document.getElementById('macChart').getContext('2d');
   const macData = JSON.parse(document.getElementById('macData').textContent);
   
   const macs = macData.map(item => item.mac.slice(-8)); // Pokazujemy tylko ostatnie 8 znaków dla czytelności
   const counts = macData.map(item => item.count);
   
   new Chart(macCtx, {
       type: 'bar',
       data: {
           labels: macs,
           datasets: [{
               label: 'Liczba pakietów',
               data: counts,
               backgroundColor: 'rgba(153, 102, 255, 0.7)',
               borderColor: 'rgba(153, 102, 255, 1)',
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
                       text: 'Adresy MAC (ostatnie 8 znaków)'
                   }
               }
           },
           plugins: {
               title: {
                   display: true,
                   text: 'Najczęściej używane adresy MAC'
               },
               tooltip: {
                   callbacks: {
                       title: function(tooltipItems) {
                           // Pokazuje pełny adres MAC w tooltipie
                           const index = tooltipItems[0].dataIndex;
                           return macData[index].mac;
                       }
                   }
               }
           }
       }
   });
}

// Wykres producentów MAC (Pie Chart)
function initVendorChart() {
   const vendorCtx = document.getElementById('vendorChart').getContext('2d');
   const vendorData = JSON.parse(document.getElementById('vendorData').textContent);
   
   const vendors = Object.keys(vendorData);
   const counts = Object.values(vendorData);
   
   new Chart(vendorCtx, {
       type: 'pie',
       data: {
           labels: vendors,
           datasets: [{
               data: counts,
               backgroundColor: [
                   'rgba(255, 99, 132, 0.7)',
                   'rgba(54, 162, 235, 0.7)',
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
                   text: 'Producenci urządzeń'
               },
               legend: {
                   position: 'right'
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

// Graf komunikacji między adresami MAC
function initMacGraph() {
   const macContainer = document.getElementById('macGraph');
   const macData = JSON.parse(document.getElementById('macGraphData').textContent);
   
   // Wykorzystanie biblioteki vis.js do wizualizacji grafu MAC
   const nodes = new vis.DataSet(macData.nodes);
   const edges = new vis.DataSet(macData.edges);
   
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
       },
       groups: {
           // Tutaj można dodać grupy kolorów dla różnych producentów urządzeń
       }
   };
   
   new vis.Network(macContainer, data, options);
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
                           <button class="nav-link" id="ethernet-tab" data-bs-toggle="tab" data-bs-target="#ethernet" type="button" role="tab">Ethernet</button>
                       </li>
                       ${packetData.ip ? `
                           <li class="nav-item" role="presentation">
                               <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip" type="button" role="tab">IP</button>
                           </li>
                       ` : ''}
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
                               ${packetData.ethernet ? `
                               <tr><th>MAC Źródło</th><td>${packetData.ethernet.src}</td></tr>
                               <tr><th>MAC Cel</th><td>${packetData.ethernet.dst}</td></tr>
                               <tr><th>Producent (Źródło)</th><td>${packetData.ethernet.src_vendor}</td></tr>
                               <tr><th>Producent (Cel)</th><td>${packetData.ethernet.dst_vendor}</td></tr>
                               ` : ''}
                               ${packetData.ip ? `
                               <tr><th>IP Źródło</th><td>${packetData.ip.src}</td></tr>
                               <tr><th>IP Cel</th><td>${packetData.ip.dst}</td></tr>
                               ` : ''}
                           </table>
                       </div>
                       ${packetData.ethernet ? `
                       <div class="tab-pane fade" id="ethernet" role="tabpanel">
                           <table class="table">
                               <tr><th>MAC Źródło</th><td>${packetData.ethernet.src}</td></tr>
                               <tr><th>MAC Cel</th><td>${packetData.ethernet.dst}</td></tr>
                               <tr><th>Typ</th><td>${packetData.ethernet.type}</td></tr>
                               <tr><th>Producent (Źródło)</th><td>${packetData.ethernet.src_vendor}</td></tr>
                               <tr><th>Producent (Cel)</th><td>${packetData.ethernet.dst_vendor}</td></tr>
                           </table>
                       </div>
                       ` : ''}
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
       const srcMac = document.getElementById('filter-src-mac').value;
       const dstMac = document.getElementById('filter-dst-mac').value;
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
           srcMac: srcMac,
           dstMac: dstMac,
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
           const srcMac = document.getElementById('filter-src-mac').value.toLowerCase();
           const dstMac = document.getElementById('filter-dst-mac').value.toLowerCase();
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
                   const srcMacIdx = 2; // MAC Źródłowe
                   const dstMacIdx = 3; // MAC Docelowe
                   const srcIdx = 5;    // Źródło IP
                   const dstIdx = 6;    // Cel IP
                   const protoIdx = 7;  // Protokół
                   const portsIdx = 8;  // Porty
                   const lengthIdx = 9; // Długość
                   
                   // Dane z wiersza
                   const rowSrcMac = data[srcMacIdx].toLowerCase();
                   const rowDstMac = data[dstMacIdx].toLowerCase();
                   const rowSrc = data[srcIdx].toLowerCase();
                   const rowDst = data[dstIdx].toLowerCase();
                   const rowProto = data[protoIdx];
                   const rowPorts = data[portsIdx];
                   const rowLength = parseInt(data[lengthIdx]) || 0;
                   
                   // Sprawdzanie warunków filtrowania
                   let match = true;
                   
                   if (srcMac && !rowSrcMac.includes(srcMac)) match = false;
                   if (dstMac && !rowDstMac.includes(dstMac)) match = false;
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
           document.getElementById('filter-src-mac').value = '';
           document.getElementById('filter-dst-mac').value = '';
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

// Generator filtrowanych raportów
function initFilteredReportGenerator() {
   const filteredReportBtn = document.getElementById('generateFilteredReportBtn');
   const filteredCSVBtn = document.getElementById('generateFilteredCSVBtn');
   
   if (filteredReportBtn) {
       // Obsługa kliknięcia przycisku "Raport z filtrów"
       filteredReportBtn.addEventListener('click', function() {
           generateFilteredExport('report');
       });
   }
   
   if (filteredCSVBtn) {
       // Obsługa kliknięcia przycisku "Filtrowany CSV"
       filteredCSVBtn.addEventListener('click', function() {
           generateFilteredExport('csv');
       });
   }
   
   // Wspólna funkcja do generowania eksportów
   function generateFilteredExport(exportType) {
       // Pobieranie wartości filtrów
       const srcMac = document.getElementById('filter-src-mac').value;
       const dstMac = document.getElementById('filter-dst-mac').value;
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
           srcMac: srcMac,
           dstMac: dstMac,
           srcIp: srcIp,
           dstIp: dstIp,
           protocol: protocol,
           port: port,
           lengthMin: lengthMin,
           lengthMax: lengthMax,
           timeStart: timeStart,
           timeEnd: timeEnd
       };
       
       // Określenie przycisku i endpointu
       let button, endpoint, loadingText, originalText;
       
       if (exportType === 'csv') {
           button = filteredCSVBtn;
           endpoint = `/export_filtered_csv/${filename}`;
           loadingText = '<i class="fas fa-spinner fa-spin"></i> Eksportowanie CSV...';
           originalText = '<i class="fas fa-file-csv"></i> Filtrowany CSV';
       } else {
           button = filteredReportBtn;
           endpoint = `/generate_filtered_report/${filename}`;
           loadingText = '<i class="fas fa-spinner fa-spin"></i> Generowanie raportu...';
           originalText = '<i class="fas fa-file-pdf"></i> Raport z filtrów';
       }
       
       // Wyświetlenie informacji o trwającym generowaniu
       button.disabled = true;
       button.innerHTML = loadingText;
       
       // Wysłanie żądania do serwera
       fetch(endpoint, {
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
           button.disabled = false;
           button.innerHTML = originalText;
           
           if (data.success) {
               // Przekierowanie do pobrania wygenerowanego pliku
               if (exportType === 'csv') {
                   window.location.href = data.csv_url;
                   // Wyświetl informację o liczbie wyeksportowanych pakietów
                   alert(`Wyeksportowano ${data.total_packets} pakietów do pliku CSV.`);
               } else {
                   window.location.href = data.report_url;
               }
           } else {
               alert(`Błąd ${exportType === 'csv' ? 'eksportu CSV' : 'generowania raportu'}: ${data.error}`);
           }
       })
       .catch(error => {
           console.error('Error:', error);
           // Przywrócenie przycisku
           button.disabled = false;
           button.innerHTML = originalText;
           alert(`Wystąpił błąd podczas ${exportType === 'csv' ? 'eksportu CSV' : 'generowania raportu'}. Sprawdź konsolę przeglądarki.`);
       });
   }
   
   // Obsługa przycisku "Zastosuj filtry"
   const applyFiltersBtn = document.getElementById('apply-filters');
   if (applyFiltersBtn) {
       applyFiltersBtn.addEventListener('click', function() {
           // Tutaj można dodać kod do filtrowania tabeli bez generowania raportu PDF
           // Na przykład filtrowanie w DataTables
           
           // Pobieranie wartości filtrów
           const srcMac = document.getElementById('filter-src-mac').value.toLowerCase();
           const dstMac = document.getElementById('filter-dst-mac').value.toLowerCase();
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
                   const srcMacIdx = 2; // MAC Źródłowe
                   const dstMacIdx = 3; // MAC Docelowe
                   const srcIdx = 5;    // Źródło IP
                   const dstIdx = 6;    // Cel IP
                   const protoIdx = 7;  // Protokół
                   const portsIdx = 8;  // Porty
                   const lengthIdx = 9; // Długość
                   
                   // Dane z wiersza
                   const rowSrcMac = data[srcMacIdx].toLowerCase();
                   const rowDstMac = data[dstMacIdx].toLowerCase();
                   const rowSrc = data[srcIdx].toLowerCase();
                   const rowDst = data[dstIdx].toLowerCase();
                   const rowProto = data[protoIdx];
                   const rowPorts = data[portsIdx];
                   const rowLength = parseInt(data[lengthIdx]) || 0;
                   
                   // Sprawdzanie warunków filtrowania
                   let match = true;
                   
                   if (srcMac && !rowSrcMac.includes(srcMac)) match = false;
                   if (dstMac && !rowDstMac.includes(dstMac)) match = false;
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
           document.getElementById('filter-src-mac').value = '';
           document.getElementById('filter-dst-mac').value = '';
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