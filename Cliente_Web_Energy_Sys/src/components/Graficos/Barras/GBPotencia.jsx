import * as echarts from "echarts";
import React, { useEffect } from "react";

const GBPotencia = () => {
  useEffect(() => {
    const chartDom = document.getElementById("GBPotencia");
    const myChart = echarts.init(chartDom);

    const option = {
      tooltip: {
        trigger: "axis",
        axisPointer: {
          type: "shadow",
        },
      },
      grid: {
        left: "3%",
        right: "4%",
        bottom: "3%",
        containLabel: true,
      },
      xAxis: [
        {
          type: "category",
          data: [
            "Lunes",
            "Martes",
            "Miercoles",
            "Jueves",
            "Viernes",
            "Sabado",
            "Domingo",
          ],
          axisTick: {
            alignWithLabel: true,
          },
        },
      ],
      yAxis: [
        {
          type: "value",
        },
      ],
      series: [
        {
          name: "Direct",
          type: "bar",
          barWidth: "60%",
          data: [10, 52, 200, 334, 390, 330, 220],
        },
      ],
    };

    myChart.setOption(option);

    return () => {
      myChart.dispose(); // Limpia el gráfico al desmontar el componente
    };
  }, []); // Asegúrate de que este efecto se ejecute solo una vez al montar el componente

  return <div id="GBPotencia" style={{ width: "100%", height: "300px" }}></div>;
};

export default GBPotencia;
