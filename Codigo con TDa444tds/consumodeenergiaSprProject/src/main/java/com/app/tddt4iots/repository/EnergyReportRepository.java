package com.app.tddt4iots.repository;
 
 import com.app.tddt4iots.entities.EnergyReport;
 import org.springframework.data.jpa.repository.JpaRepository;
 import java.util.*;
import java.lang.*;

 public interface EnergyReportRepository extends JpaRepository<EnergyReport, Long> {
 }
