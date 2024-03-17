"use client";
import { createChart, ColorType } from "lightweight-charts";
import React, { useEffect, useRef } from "react";

export const GraficoPotencia = (props) => {
  const {
    data,
    colors: {
      backgroundColor = "white",
      lineColor = "rgba( 239, 83, 80, 1)",
      textColor = "black",
      areaTopColor = "white",
      areaBottomColor = "rgba(255, 255, 255, 0)",
    } = {},
  } = props;

  const chartContainerRef = useRef();

  useEffect(() => {
    const handleResize = () => {
      chart.applyOptions({ width: chartContainerRef.current.clientWidth });
    };

    const chart = createChart(chartContainerRef.current, {
      layout: {
        background: { type: ColorType.Solid, color: backgroundColor },
        textColor,
      },
      width: chartContainerRef.current.clientWidth,
      height: 200,
    });
    chart.timeScale().fitContent();

    const newSeries = chart.addAreaSeries({
      lineColor,
      topColor: areaTopColor,
      bottomColor: areaBottomColor,
    });
    newSeries.setData(data);

    //Nuevo Incicio

    chart.applyOptions({
      leftPriceScale: {
        visible: false,
        borderVisible: true,
      },
      rightPriceScale: {
        visible: true,
        borderVisible: true,
      },
      timeScale: {
        borderVisible: true,
      },
      crosshair: {
        horzLine: {
          visible: false,
          labelVisible: false,
        },
        vertLine: {
          visible: true,
          style: 0,
          width: 2,
          color: "rgba(32, 38, 46, 0.1)",
          labelVisible: true,
        },
      },
      // hide the grid lines
      grid: {
        vertLines: {
          visible: true,
        },
        horzLines: {
          visible: true,
        },
      },
    });

    const container = chartContainerRef.current;
    const toolTip = document.createElement("div");
    toolTip.style = `width: 96px; height: 100px; position: absolute; display: none; padding: 8px; box-sizing: border-box; font-size: 12px; text-align: left; z-index: 1000; top: 12px; left: 12px; pointer-events: none; border-radius: 4px 4px 0px 0px; border-bottom: none; box-shadow: 0 2px 5px 0 rgba(117, 134, 150, 0.45);font-family: -apple-system, BlinkMacSystemFont, 'Trebuchet MS', Roboto, Ubuntu, sans-serif; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;`;
    toolTip.style.background = `rgba(0, 0, 0, 0.25)`;
    toolTip.style.color = "white";
    toolTip.style.borderColor = "rgba(239, 83, 80, 1)";
    container.appendChild(toolTip);

    const toolTipWidth = 80;
    const toolTipHeight = 80;
    const toolTipMargin = 15;

    chart.subscribeCrosshairMove((param) => {
      if (
        param.point === undefined ||
        !param.time ||
        param.point.x < 0 ||
        param.point.x > container.clientWidth ||
        param.point.y < 0 ||
        param.point.y > container.clientHeight
      ) {
        toolTip.style.display = "none";
      } else {
        //OPCION 1 para mostrar
        /*
            // time will be in the same format that we supplied to setData.
            // thus it will be YYYY-MM-DD
            const dateStr = param.time;
            toolTip.style.display = 'block';
            const data = param.seriesData.get(newSeries);
            const price = data.value !== undefined ? data.value : data.close;
            toolTip.innerHTML = `<div style="color: ${'rgba( 239, 83, 80, 1)'}">⬤ Potencia </div><div style="font-size: 24px; margin: 4px 0px; color: ${'white'}">
                ${Math.round(100 * price) / 100}
                </div><div style="color: ${'white'}">
                ${dateStr}
                </div>`;
    
            let left = param.point.x; // relative to timeScale
            const timeScaleWidth = chart.timeScale().width();
            const priceScaleWidth = chart.priceScale('left').width();
            const halfTooltipWidth = toolTipWidth / 2;
            left += priceScaleWidth - halfTooltipWidth;
            left = Math.min(left, priceScaleWidth + timeScaleWidth - toolTipWidth);
            left = Math.max(left, priceScaleWidth);
    
            toolTip.style.left = left + 'px';
            toolTip.style.top = 200 + 'px';
            */
        //OPCION 2 para mostrar

        const dateStr = param.time;
        toolTip.style.display = "block";
        const data = param.seriesData.get(newSeries);
        const price = data.value !== undefined ? data.value : data.close;
        toolTip.innerHTML = `<div style="color: ${"rgba( 239, 83, 80, 1)"}">Potencia</div><div style="font-size: 24px; margin: 4px 0px; color: ${"white"}">
               ${Math.round(100 * price) / 100}
               </div><div style="color: ${"white"}">
               ${dateStr}
               </div>`;

        const y = param.point.y;
        let left = param.point.x + toolTipMargin;
        if (left > container.clientWidth - toolTipWidth) {
          left = param.point.x - toolTipMargin - toolTipWidth;
        }

        let top = y + toolTipMargin;
        if (top > container.clientHeight - toolTipHeight) {
          top = y - toolTipHeight - toolTipMargin;
        }
        toolTip.style.left = left + "px";
        toolTip.style.top = top + "px";
      }
    });

    //Nuevo fin

    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);

      chart.remove();
      container.removeChild(toolTip);
    };
  }, [
    data,
    backgroundColor,
    lineColor,
    textColor,
    areaTopColor,
    areaBottomColor,
  ]);

  return <div ref={chartContainerRef} />;
};
