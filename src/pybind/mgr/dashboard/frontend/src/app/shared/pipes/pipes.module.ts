import { CommonModule, DatePipe } from '@angular/common';
import { NgModule } from '@angular/core';

import { CdDatePipe } from './cd-date.pipe';
import { CephShortVersionPipe } from './ceph-short-version.pipe';
import { DimlessBinaryPipe } from './dimless-binary.pipe';
import { DimlessPipe } from './dimless.pipe';
import { FilterPipe } from './filter.pipe';
import { HealthColorPipe } from './health-color.pipe';
import { ListPipe } from './list.pipe';
import { RelativeDatePipe } from './relative-date.pipe';

@NgModule({
  imports: [CommonModule],
  declarations: [
    DimlessBinaryPipe,
    HealthColorPipe,
    DimlessPipe,
    CephShortVersionPipe,
    RelativeDatePipe,
    ListPipe,
    FilterPipe,
    CdDatePipe
  ],
  exports: [
    DimlessBinaryPipe,
    HealthColorPipe,
    DimlessPipe,
    CephShortVersionPipe,
    RelativeDatePipe,
    ListPipe,
    FilterPipe,
    CdDatePipe
  ],
  providers: [
    DatePipe,
    CephShortVersionPipe,
    DimlessBinaryPipe,
    DimlessPipe,
    RelativeDatePipe,
    ListPipe,
    CdDatePipe
  ]
})
export class PipesModule {}
