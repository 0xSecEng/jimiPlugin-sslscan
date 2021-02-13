
new Chart(document.getElementById("doughnut-chart"), {
    type: 'doughnut',
    data: {
      labels: chartLabels,
      datasets: [
        {
        backgroundColor: ChartColours,

          data: pieChartData
        }
      ]
    },
    options: {
        cutoutPercentage: 75,
        legend: {
                position: 'bottom',
                labels: {
                    fontColor: "black",
                    fontSize: 12
                }
            },        
      title: {
        display: true,
        fontSize: 16,
        fontColor: "black",
        text: pieTitle
      }
    }
});