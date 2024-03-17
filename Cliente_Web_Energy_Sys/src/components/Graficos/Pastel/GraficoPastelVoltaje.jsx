import * as echarts from 'echarts';
import React, { useEffect } from "react";

const GraficoPastelVoltaje = () => {
useEffect(() => {
  const chartDom = document.getElementById("GAPVoltaje");
  const myChart = echarts.init(chartDom);

  const option = {
    series: [
      {
        type: "gauge",
        center: ["50%", "60%"],
        startAngle: 200,
        endAngle: -20,
        min: 0,
        max: 150,
        splitNumber: 10,
        itemStyle: {
          color: "mediumorchid",
        },
        progress: {
          show: true,
          width: 30,
        },
        pointer: {
          show: false,
        },
        axisLine: {
          lineStyle: {
            width: 30,
          },
        },
        axisTick: {
          distance: -45,
          splitNumber: 5,
          lineStyle: {
            width: 2,
            color: "#999",
          },
        },
        splitLine: {
          distance: -52,
          length: 14,
          lineStyle: {
            width: 3,
            color: "#999",
          },
        },
        axisLabel: {
          distance: -10,
          color: "black",
          fontSize: 10,
        },
        anchor: {
          show: false,
        },
        title: {
          show: false,
        },
        detail: {
          valueAnimation: true,
          width: "100%",
          lineHeight: 40,
          borderRadius: 8,
          offsetCenter: [0, "-15%"],
          fontSize: 20,
          fontWeight: "bolder",
          formatter: "{value} V",
          color: "inherit",
        },
        data: [
          {
            value: 20,
          },
        ],
      },
      {
        type: "gauge",
        center: ["50%", "60%"],
        startAngle: 200,
        endAngle: -20,
        min: 0,
        max: 100,
        itemStyle: {
          color: "purple",
        },
        progress: {
          show: true,
          width: 8,
        },
        pointer: {
          show: false,
        },
        axisLine: {
          show: false,
        },
        axisTick: {
          show: false,
        },
        splitLine: {
          show: false,
        },
        axisLabel: {
          show: false,
        },
        detail: {
          show: false,
        },
        data: [
          {
            value: 20,
          },
        ],
      },
    ],
  };

  setInterval(function () {
    const random = +(Math.random() * 60).toFixed(2);
    myChart.setOption({
      series: [
        {
          data: [
            {
              value: random,
            },
          ],
        },
        {
          data: [
            {
              value: random,
            },
          ],
        },
      ],
    });
  }, 2000);

  myChart.setOption(option);

  return () => {
    myChart.dispose(); // Limpia el gráfico al desmontar el componente
  };
}, []); // Asegúrate de que este efecto se ejecute solo una vez al montar el componente

return <div id="GAPVoltaje" style={{ width: "100%", height: "220px" }}></div>;
};

export default GraficoPastelVoltaje;
