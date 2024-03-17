import React, { useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import SidebarLinkGroup from "./SidebarLinkGroup";
import { RxDashboard } from "react-icons/rx";
import { RiAccountCircleLine } from "react-icons/ri";
import { IoSettingsOutline } from "react-icons/io5";
import { FaRegWindowClose } from "react-icons/fa";
import { FaHome } from "react-icons/fa";
import { TbHistoryToggle } from "react-icons/tb";
import { TbReportSearch } from "react-icons/tb";
import { RiBarChartFill } from "react-icons/ri";
import { IoMdPulse } from "react-icons/io";
import { Loader } from "@/widgets";
import { useRouter } from "next/router";

const Sidebar = ({ sidebarOpen, setSidebarOpen }) => {
  const router = useRouter();
  //variable para mostrar el loader cuando carga una peticion
  const [load, setLoader] = useState(false);

  const DarNavegacion = async (href) => {
    setLoader(true); // Mostrar el loader al hacer clic en un enlace
    await router.push(href); // Navegar a la página correspondiente
    setLoader(false); // Ocultar el loader después de que se cargue la página
  };

  const pathname = usePathname();

  const trigger = useRef(null);
  const sidebar = useRef(null);

  let storedSidebarExpanded = "true";

  const [sidebarExpanded, setSidebarExpanded] = useState(
    storedSidebarExpanded === null ? false : storedSidebarExpanded === "true"
  );

  // Cierra la barra si presiono dentro del datos
  /*
  useEffect(() => {
    const clickHandler = ({ target }) => {
      if (!sidebar.current || !trigger.current) return;
      if (
        !sidebarOpen ||
        sidebar.current.contains(target) ||
        trigger.current.contains(target)
      )
        return;
      setSidebarOpen(false);
    };
    document.addEventListener("click", clickHandler);
    return () => document.removeEventListener("click", clickHandler);
  });
*/

  // close if the esc key is pressed
  useEffect(() => {
    const keyHandler = ({ key }) => {
      if (!sidebarOpen || key !== "Escape") return;
      setSidebarOpen(false);
    };
    document.addEventListener("keydown", keyHandler);
    return () => document.removeEventListener("keydown", keyHandler);
  });

  useEffect(() => {
    localStorage.setItem("sidebar-expanded", sidebarExpanded.toString());
    if (sidebarExpanded) {
      document.querySelector("body")?.classList.add("sidebar-expanded");
    } else {
      document.querySelector("body")?.classList.remove("sidebar-expanded");
    }
  }, [sidebarExpanded]);

  return (
    <aside
      ref={sidebar}
      className={`absolute left-0 top-0 z-9999 flex h-screen w-72.5 flex-col overflow-y-hidden bg-black duration-300 ease-linear dark:bg-boxdark ${
        sidebarOpen ? "translate-x-0 lg:relative" : "-translate-x-full"
      }`}
    >
      {/* <!-- SIDEBAR HEADER --> */}
      {load ? <Loader /> : ""}
      <div className="flex items-center justify-between gap-2 px-6 py-5.5 lg:py-6.5">
        <Link href="Home">
          <Image
            width={176}
            height={32}
            src={"/img/Logos/Logo texto.png"}
            alt="Logo"
            priority
          />
        </Link>

        <button
          ref={trigger}
          onClick={() => setSidebarOpen(!sidebarOpen)}
          aria-controls="sidebar"
          aria-expanded={sidebarOpen}
          className="block"
        >
          <svg
            className="fill-current text-whiter"
            width="40"
            height="40"
            viewBox="0 0 20 18"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <FaRegWindowClose />
          </svg>
        </button>
      </div>
      {/* <!-- SIDEBAR HEADER --> */}

      <div className="no-scrollbar flex flex-col overflow-y-auto duration-300 ease-linear">
        {/* <!-- Sidebar Menu --> */}
        <nav className="mt-5 px-4 py-4 lg:mt-9 lg:px-6">
          {/* <!-- Menu Group --> */}
          <div>
            <h3 className="mb-4 ml-4 text-sm font-semibold text-bodydark2">
              MENU
            </h3>

            <ul className="mb-6 flex flex-col gap-1.5">
              {/* <!-- Menu Item Panel Principal --> */}
              <SidebarLinkGroup
                activeCondition={
                  pathname === "/" || pathname.includes("dashboard")
                }
              >
                {(handleClick, open) => {
                  return (
                    <React.Fragment>
                      <Link
                        href="#"
                        className={`group relative flex items-center gap-2.5 rounded-sm px-4 py-2 font-medium text-bodydark1 duration-300 ease-in-out hover:bg-graydark dark:hover:bg-meta-4 ${
                          (pathname === "/" ||
                            pathname.includes("dashboard")) &&
                          "bg-graydark dark:bg-meta-4"
                        }`}
                        onClick={(e) => {
                          e.preventDefault();
                          sidebarExpanded
                            ? handleClick()
                            : setSidebarExpanded(true);
                        }}
                      >
                        <svg
                          className="fill-current"
                          width="25"
                          height="25"
                          viewBox="0 0 18 18"
                          fill="none"
                          xmlns="http://www.w3.org/2000/vg"
                        >
                          <RxDashboard />
                        </svg>
                        Panel Principal
                        <svg
                          className={`absolute right-4 top-1/2 -translate-y-1/2 fill-current ${
                            open && "rotate-180"
                          }`}
                          width="25"
                          height="25"
                          viewBox="0 0 20 20"
                          fill="none"
                          xmlns="http://www.w3.org/2000/svg"
                        >
                          <path
                            fillRule="evenodd"
                            clipRule="evenodd"
                            d="M4.41107 6.9107C4.73651 6.58527 5.26414 6.58527 5.58958 6.9107L10.0003 11.3214L14.4111 6.91071C14.7365 6.58527 15.2641 6.58527 15.5896 6.91071C15.915 7.23614 15.915 7.76378 15.5896 8.08922L10.5896 13.0892C10.2641 13.4147 9.73651 13.4147 9.41107 13.0892L4.41107 8.08922C4.08563 7.76378 4.08563 7.23614 4.41107 6.9107Z"
                            fill=""
                          />
                        </svg>
                      </Link>
                      {/* <!-- Dropdown Menu Start --> */}
                      <div
                        className={`translate transform overflow-hidden ${
                          !open && "hidden"
                        }`}
                      >
                        <ul className="mb-5.5 mt-4 flex flex-col gap-2.5 pl-6">
                          <li>
                            <Link
                              href="/dashboard/Home"
                              onClick={() => DarNavegacion("/dashboard/Home")}
                              className={`group relative flex items-center gap-2.5 rounded-sm px-4 py-2 font-medium text-bodydark1 duration-300 ease-in-out hover:bg-graydark dark:hover:bg-meta-4 ${
                                pathname.includes("profile") &&
                                "bg-graydark dark:bg-meta-4"
                              }`}
                            >
                              <svg
                                className="fill-current"
                                width="25"
                                height="25"
                                viewBox="0 0 18 18"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <FaHome />
                              </svg>
                              Home
                            </Link>
                          </li>
                          <li>
                            <Link
                              href="/dashboard/Lecturas"
                              onClick={() =>
                                DarNavegacion("/dashboard/Lecturas")
                              }
                              className={`group relative flex items-center gap-2.5 rounded-sm px-4 py-2 font-medium text-bodydark1 duration-300 ease-in-out hover:bg-graydark dark:hover:bg-meta-4 ${
                                pathname.includes("Lecturas") &&
                                "bg-graydark dark:bg-meta-4"
                              }`}
                            >
                              <svg
                                className="fill-current"
                                width="25"
                                height="25"
                                viewBox="0 0 18 18"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <IoMdPulse />
                              </svg>
                              Lecturas
                            </Link>
                          </li>
                          <li>
                            <Link
                              href="/dashboard/Estadisticas"
                              onClick={() =>
                                DarNavegacion("/dashboard/Estadisticas")
                              }
                              className={`group relative flex items-center gap-2.5 rounded-sm px-4 py-2 font-medium text-bodydark1 duration-300 ease-in-out hover:bg-graydark dark:hover:bg-meta-4 ${
                                pathname.includes("Estadisticas") &&
                                "bg-graydark dark:bg-meta-4"
                              }`}
                            >
                              <svg
                                className="fill-current"
                                width="25"
                                height="25"
                                viewBox="0 0 18 18"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <RiBarChartFill />
                              </svg>
                              Estadísticas
                            </Link>
                          </li>
                          <li>
                            <Link
                              href="/dashboard/Historico"
                              onClick={() =>
                                DarNavegacion("/dashboard/Historico")
                              }
                              className={`group relative flex items-center gap-2.5 rounded-sm px-4 py-2 font-medium text-bodydark1 duration-300 ease-in-out hover:bg-graydark dark:hover:bg-meta-4 ${
                                pathname.includes("Historico") &&
                                "bg-graydark dark:bg-meta-4"
                              }`}
                            >
                              <svg
                                className="fill-current"
                                width="25"
                                height="25"
                                viewBox="0 0 18 18"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <TbHistoryToggle />
                              </svg>
                              Histórico
                            </Link>
                          </li>
                          <li>
                            <Link
                              href="/dashboard/Reportes"
                              onClick={() =>
                                DarNavegacion("/dashboard/Reportes")
                              }
                              className={`group relative flex items-center gap-2.5 rounded-sm px-4 py-2 font-medium text-bodydark1 duration-300 ease-in-out hover:bg-graydark dark:hover:bg-meta-4 ${
                                pathname.includes("Reportes") &&
                                "bg-graydark dark:bg-meta-4"
                              }`}
                            >
                              <svg
                                className="fill-current"
                                width="25"
                                height="25"
                                viewBox="0 0 18 18"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <TbReportSearch />
                              </svg>
                              Reportes
                            </Link>
                          </li>
                        </ul>
                      </div>
                      {/* <!-- Dropdown Menu End --> */}
                    </React.Fragment>
                  );
                }}
              </SidebarLinkGroup>
              {/* <!-- Menu Item Panel Principal --> */}

              {/* <!-- Menu Item Perfil --> */}
              <li>
                <Link
                  href="/dashboard/Usuario"
                  onClick={() => DarNavegacion("/dashboard/Usuario")}
                  className={`group relative flex items-center gap-2.5 rounded-sm px-4 py-2 font-medium text-bodydark1 duration-300 ease-in-out hover:bg-graydark dark:hover:bg-meta-4 ${
                    pathname.includes("Usuario") && "bg-graydark dark:bg-meta-4"
                  }`}
                >
                  <svg
                    className="fill-current"
                    width="25"
                    height="25"
                    viewBox="0 0 18 18"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <RiAccountCircleLine />
                  </svg>
                  Perfil
                </Link>
              </li>
              {/* <!-- Menu Item Perfil --> */}

              {/* <!-- Menu Item configuracion --> */}
              <li>
                <Link
                  href="Configuracion"
                  onClick={() => DarNavegacion("/dashboard/Configuracion")}
                  className={`group relative flex items-center gap-2.5 rounded-sm px-4 py-2 font-medium text-bodydark1 duration-300 ease-in-out hover:bg-graydark dark:hover:bg-meta-4 ${
                    pathname.includes("configuracion") &&
                    "bg-graydark dark:bg-meta-4"
                  }`}
                >
                  <svg
                    className="fill-current"
                    width="25"
                    height="25"
                    viewBox="0 0 18 19"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <IoSettingsOutline />
                  </svg>
                  Configuración
                </Link>
              </li>
              {/* <!-- Menu Item configuracion --> */}
            </ul>
          </div>
        </nav>
        {/* <!-- Sidebar Menu --> */}
      </div>
    </aside>
  );
};

export default Sidebar;
