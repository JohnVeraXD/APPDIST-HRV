"use client";
import React, { useEffect, useState } from "react";
import TituloPagina from "@/components/Titulo/titulopagina";
import CardDataStats from "@/components/Cards/CardDataStats";
import { FaPlugCircleBolt } from "react-icons/fa6";
import { IoCalendarNumberOutline } from "react-icons/io5";
import { FaMoneyBillWave } from "react-icons/fa";
import GBPotencia from "@/components/Graficos/Barras/GBPotencia";

const Estadisticas = () => {
  return (
    <div className="mx-auto max-w-7xl">
      <TituloPagina nombrepagina="Estadisticas" />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 md:gap-6 xl:grid-cols-3 2xl:gap-7.5 ">
        <CardDataStats
          title="Total Ayer:"
          total="0.0KW/h"
          rate="0%"
          levelUp
          text="Ayer:"
        >
          <svg
            className="fill-primary dark:fill-white"
            width="40"
            height="40"
            viewBox="-5 0 22 16"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <FaPlugCircleBolt className=" text-blue-gray-900 dark:text-light-blue-300" />
          </svg>
        </CardDataStats>
        <CardDataStats
          title="Total Mes Pasado:"
          total="123KW/h"
          rate="0%"
          levelUp
          text="Mes Pasado:"
        >
          <svg
            className="fill-primary dark:fill-white"
            width="40"
            height="40"
            viewBox="-4 0 22 16"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <IoCalendarNumberOutline className=" text-blue-gray-900 dark:text-light-blue-300" />
          </svg>
        </CardDataStats>
        <CardDataStats
          title="Total a Pagar:"
          total="13.05$"
          rate="0%"
          levelUp
          text="Total a Pagar:"
        >
          <svg
            className="fill-primary dark:fill-white"
            width="40"
            height="40"
            viewBox="-4 0 22 16"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <FaMoneyBillWave className=" text-blue-gray-900 dark:text-lime-300" />
          </svg>
        </CardDataStats>
      </div>

      <div className=" mt-6 grid grid-cols-1 gap-4 md:grid-cols-1 md:gap-6 xl:grid-cols-1 2xl:gap-7.5">
        <div className="rounded-sm border border-stroke bg-white px-7.5 py-6 shadow-default dark:border-strokedark dark:bg-boxdark">
        <h2 className=" text-title-sm2 font-semibold text-black dark:text-white text-center pb-2 pl-5">
          Potencia
          </h2>
          <div className="flex items-center">
          <h2 className=" text-black dark:text-white text-left pl-0">
          Watts
          </h2>
            <GBPotencia />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Estadisticas;
