import React from "react";
import "@/styles/globals.css";
import DefaultLayout from "@/components/Layouts/DefaultLayout";
import Perfil_Usuarios from "./Perfil_Usuario";
import { useState } from "react";

export default function Index_Usuario() {
  //variable para mostrar el loader cuando carga una peticion
  const [load, setLoader] = useState(false);
  return (
    <DefaultLayout>
      <Perfil_Usuarios />
    </DefaultLayout>
  );
}
