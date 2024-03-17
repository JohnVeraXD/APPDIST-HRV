"use client";
import React, { useEffect, useState } from "react";
import TituloPagina from "@/components/Titulo/titulopagina";
import dynamic from "next/dynamic";
import { Typography } from "@material-tailwind/react";

const GraficoPastel1 = dynamic(
  () => import("@/components/Graficos/Pastel/GraficoPastel1"),
  {
    ssr: false, // Evita que se renderice en el servidor
  }
);

import { GraficoPotencia } from "@/components/Graficos/Lineas/GraficoPotencia";

import { GraficoCorriente } from "@/components/Graficos/Lineas/GraficoCorriente";

//import Graficalineas3 from "@/components/Graficos/Lineas/GraficoLineas3";

import GAPPotencia from "@/components/Graficos/Pastel/GraficoPastelPotencia";

import GAPCorriente from "@/components/Graficos/Pastel/GraficoPastelCorriente";

import GAPVoltaje from "@/components/Graficos/Pastel/GraficoPastelVoltaje";

import GAFPotencia from "@/components/Graficos/Pastel/GraficoPastelFPotencia";

const dataPotencia = [
  { time: "2018-12-22", value: 32.51 },
  { time: "2018-12-23", value: 31.11 },
  { time: "2018-12-24", value: 27.02 },
  { time: "2018-12-25", value: 27.32 },
  { time: "2018-12-26", value: 25.17 },
  { time: "2018-12-27", value: 28.89 },
  { time: "2018-12-28", value: 25.46 },
  { time: "2019-01-01", value: 23.92 },
  { time: "2019-01-02", value: 24.68 },
  { time: "2019-01-03", value: 26.67 },
  { time: "2019-01-04", value: 28.67 },
  { time: "2019-01-05", value: 70.67 },
  { time: "2019-02-01", value: 43.67 },
  { time: "2019-02-02", value: 10.67 },
  { time: "2019-02-03", value: 80.67 },
];

const dataCorriente = [
  { time: "2019-12-22", value: 32.51 },
  { time: "2019-12-23", value: 31.11 },
  { time: "2019-12-24", value: 27.02 },
  { time: "2019-12-25", value: 27.32 },
  { time: "2019-12-26", value: 25.17 },
  { time: "2019-12-27", value: 28.89 },
  { time: "2019-12-28", value: 25.46 },
  { time: "2020-01-01", value: 23.92 },
  { time: "2020-01-02", value: 24.68 },
  { time: "2020-01-03", value: 26.67 },
  { time: "2020-01-04", value: 28.67 },
  { time: "2020-01-05", value: 70.67 },
  { time: "2020-02-01", value: 43.67 },
  { time: "2020-02-02", value: 10.67 },
  { time: "2020-02-03", value: 80.67 },
];

const Lecturas = () => {
  return (
    <div className="mx-auto max-w-7xl">
      <TituloPagina nombrepagina="Lecturas" />
      <div className="grid grid-cols-12 gap-4 md:gap-4 2xl:gap-5">
        {/*<div className="col-span-12 md:col-span-8">
          <GraficoLineas1 />
  </div>*/}
        {/*<div className="col-span-12 md:col-span-4">
          <GraficoPastel1 />
        </div>*/}
        {/* <div className="col-span-12 md:col-span-8">
          <Graficalineas3 />
        </div>*/}
        <div className="col-span-12 rounded-sm border border-stroke bg-white px-2 pb-1 pt-2 shadow-default dark:border-strokedark dark:bg-boxdark sm:px-5 xl:col-span-8">
          <h2 className=" text-title-sm2 font-semibold text-black dark:text-white text-left pb-2 ">
            Potencia
          </h2>
          <GraficoPotencia data={dataPotencia}></GraficoPotencia>
        </div>
        <div className="col-span-12 md:col-span-12 xl:col-span-4 rounded-sm border border-stroke bg-white px-2 pb-2 pt-5 shadow-default dark:border-strokedark dark:bg-boxdark sm:px-2">
          <h2 className=" text-title-sm2 font-semibold text-black dark:text-white text-left pb-2  pl-5">
            Potencia
          </h2>
          <GAPPotencia />
        </div>
        <div className="col-span-12 rounded-sm border border-stroke bg-white px-2 pb-2 pt-5 shadow-default dark:border-strokedark dark:bg-boxdark sm:px-5 xl:col-span-8">
          <h2 className=" text-title-sm2 font-semibold text-black dark:text-white text-left pb-2  w-100%">
            Corriente
          </h2>
          <GraficoCorriente data={dataCorriente}></GraficoCorriente>
        </div>
        <div className="col-span-12 md:col-span-12  xl:col-span-4 rounded-sm border border-stroke bg-white px-2 pb-2 pt-5 shadow-default dark:border-strokedark dark:bg-boxdark sm:px-2">
          <h2 className=" text-title-sm2 font-semibold text-black dark:text-white text-left pb-2 pl-5">
          Corriente
          </h2>
          <GAPCorriente />
        </div>
        <div className="col-span-12 md:col-span-12  xl:col-span-4 rounded-sm border border-stroke bg-white px-2 pb-2 pt-5 shadow-default dark:border-strokedark dark:bg-boxdark sm:px-2">
          <h2 className=" text-title-sm2 font-semibold text-black dark:text-white text-left pb-2 pl-5">
          Voltaje
          </h2>
          <GAPVoltaje />
        </div>
        <div className="col-span-12 md:col-span-12  xl:col-span-4 rounded-sm border border-stroke bg-white px-2 pb-2 pt-5 shadow-default dark:border-strokedark dark:bg-boxdark sm:px-2">
          <h2 className=" text-title-sm2 font-semibold text-black dark:text-white text-left pb-2 pl-5">
          Factor Potencia
          </h2>
          <GAFPotencia />
        </div>
      </div>
    </div>
  );
};

export default Lecturas;
